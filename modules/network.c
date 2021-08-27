#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

#include <threads.h>
#include <poll.h>

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <linux/nl80211.h>

#include <tllist.h>

#define LOG_MODULE "network"
#define LOG_ENABLE_DBG 0
#include "../log.h"
#include "../bar/bar.h"
#include "../config.h"
#include "../config-verify.h"
#include "../module.h"
#include "../plugin.h"

#define UNUSED __attribute__((unused))

struct af_addr {
    int family;
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    } addr;
};

struct private {
    char *iface;
    struct particle *label;

    int genl_sock;
    int rt_sock;

    struct {
        uint16_t family_id;
        uint32_t seq_nr;
    } nl80211;

    bool get_addresses;

    int ifindex;
    uint8_t mac[6];
    bool carrier;
    uint8_t state;  /* IFLA_OPERSTATE */

    /* IPv4 and IPv6 addresses */
    tll(struct af_addr) addrs;

    /* WiFi extensions */
    char *ssid;
};

static void
destroy(struct module *mod)
{
    struct private *m = mod->private;

    assert(m->rt_sock == -1);

    m->label->destroy(m->label);

    tll_free(m->addrs);
    free(m->ssid);
    free(m->iface);
    free(m);

    module_default_destroy(mod);
}

static const char *
description(struct module *mod)
{
    static char desc[32];
    struct private *m = mod->private;

    snprintf(desc, sizeof(desc), "net(%s)", m->iface);
    return desc;
}

static struct exposable *
content(struct module *mod)
{
    struct private *m = mod->private;

    mtx_lock(&mod->lock);

    const char *state = NULL;
    switch (m->state) {
    case IF_OPER_UNKNOWN:         state = "unknown"; break;
    case IF_OPER_NOTPRESENT:      state = "not present"; break;
    case IF_OPER_DOWN:            state = "down"; break;
    case IF_OPER_LOWERLAYERDOWN:  state = "lower layers down"; break;
    case IF_OPER_TESTING:         state = "testing"; break;
    case IF_OPER_DORMANT:         state = "dormant"; break;
    case IF_OPER_UP:              state = "up"; break;
    default:                      state = "unknown"; break;
    }

    char mac_str[6 * 2 + 5 + 1];
    char ipv4_str[INET_ADDRSTRLEN] = {0};
    char ipv6_str[INET6_ADDRSTRLEN] = {0};

    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             m->mac[0], m->mac[1], m->mac[2], m->mac[3], m->mac[4], m->mac[5]);

    /* TODO: this exposes the *last* added address of each kind. Can
     * we expose all in some way? */
    tll_foreach(m->addrs, it) {
        if (it->item.family == AF_INET)
            inet_ntop(AF_INET, &it->item.addr.ipv4, ipv4_str, sizeof(ipv4_str));
        else if (it->item.family == AF_INET6)
            inet_ntop(AF_INET6, &it->item.addr.ipv6, ipv6_str, sizeof(ipv6_str));
    }

    struct tag_set tags = {
        .tags = (struct tag *[]){
            tag_new_string(mod, "name", m->iface),
            tag_new_int(mod, "index", m->ifindex),
            tag_new_bool(mod, "carrier", m->carrier),
            tag_new_string(mod, "state", state),
            tag_new_string(mod, "mac", mac_str),
            tag_new_string(mod, "ipv4", ipv4_str),
            tag_new_string(mod, "ipv6", ipv6_str),
            tag_new_string(mod, "ssid", m->ssid),
        },
        .count = 8,
    };

    mtx_unlock(&mod->lock);

    struct exposable *exposable =  m->label->instantiate(m->label, &tags);
    tag_set_destroy(&tags);
    return exposable;
}

/* Returns a value suitable for nl_pid/nlmsg_pid */
static uint32_t
nl_pid_value(void)
{
    return (pid_t)(uintptr_t)thrd_current() ^ getpid();
}

/* Connect and bind to netlink socket. Returns socket fd, or -1 on error */
static int
netlink_connect_rt(void)
{
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock == -1) {
        LOG_ERRNO("failed to create netlink socket");
        return -1;
    }

    const struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = nl_pid_value(),
        .nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
    };

    if (bind(sock, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERRNO("failed to bind netlink RT socket");
        close(sock);
        return -1;
    }

    return sock;
}

static int
netlink_connect_genl(void)
{
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (sock == -1) {
        LOG_ERRNO("failed to create netlink socket");
        return -1;
    }

    const struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = nl_pid_value(),
        /* no multicast notifications by default, will be added later */
    };

    if (bind(sock, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERRNO("failed to bind netlink socket");
        close(sock);
        return -1;
    }

    return sock;
}

static bool
send_nlmsg(int sock, const void *nlmsg, size_t len)
{
    int r = sendto(
        sock, nlmsg, len, 0,
        (struct sockaddr *)&(struct sockaddr_nl){.nl_family = AF_NETLINK},
        sizeof(struct sockaddr_nl));

    return r == len;
}

static bool
send_rt_request(struct private *m, int request)
{
    struct {
        struct nlmsghdr hdr;
        struct rtgenmsg rt __attribute__((aligned(NLMSG_ALIGNTO)));
    } req = {
        .hdr = {
            .nlmsg_len = NLMSG_LENGTH(sizeof(req.rt)),
            .nlmsg_type = request,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
            .nlmsg_seq = 1,
            .nlmsg_pid = nl_pid_value(),
        },

        .rt = {
            .rtgen_family = AF_UNSPEC,
        },
    };

    if (!send_nlmsg(m->rt_sock, &req, req.hdr.nlmsg_len)) {
        LOG_ERRNO("%s: failed to send netlink RT request (%d)",
                  m->iface, request);
        return false;
    }

    return true;
}

static bool
send_ctrl_get_family_request(struct private *m)
{
    const struct {
        struct nlmsghdr hdr;
        struct {
            struct genlmsghdr genl;
            struct {
                struct nlattr hdr;
                char data[8] __attribute__((aligned(NLA_ALIGNTO)));
            } family_name_attr __attribute__((aligned(NLA_ALIGNTO)));
        } msg __attribute__((aligned(NLMSG_ALIGNTO)));
    } req = {
        .hdr = {
            .nlmsg_len = NLMSG_LENGTH(sizeof(req.msg)),
            .nlmsg_type = GENL_ID_CTRL,
            .nlmsg_flags = NLM_F_REQUEST,
            .nlmsg_seq = 1,
            .nlmsg_pid = nl_pid_value(),
        },

        .msg = {
            .genl = {
                .cmd = CTRL_CMD_GETFAMILY,
                .version = 1,
            },

            .family_name_attr = {
                .hdr = {
                    .nla_type = CTRL_ATTR_FAMILY_NAME,
                    .nla_len = sizeof(req.msg.family_name_attr),
                },

                .data = NL80211_GENL_NAME,
            },
        },
    };

    _Static_assert(
        sizeof(req.msg.family_name_attr) ==
        NLA_HDRLEN + NLA_ALIGN(sizeof(req.msg.family_name_attr.data)),
        "");

    if (!send_nlmsg(m->genl_sock, &req, req.hdr.nlmsg_len)) {
        LOG_ERRNO("%s: failed to send netlink ctrl-get-family request",
                  m->iface);
        return false;
    }

    return true;
}

static bool
send_nl80211_get_interface_request(struct private *m)
{
    if (m->ifindex < 0)
        return true;

    if (m->nl80211.seq_nr > 0) {
        LOG_DBG(
            "%s: nl80211 get-interface request already in progress", m->iface);
        return true;
    }

    m->nl80211.seq_nr = time(NULL);
    LOG_DBG("%s: sending nl80211 get-interface request", m->iface);

    const struct {
        struct nlmsghdr hdr;
        struct {
            struct genlmsghdr genl;
            struct {
                struct nlattr attr;
                int index __attribute__((aligned(NLA_ALIGNTO)));
            } ifindex __attribute__((aligned(NLA_ALIGNTO)));
        } msg __attribute__((aligned(NLMSG_ALIGNTO)));
    } req = {
        .hdr = {
            .nlmsg_len = NLMSG_LENGTH(sizeof(req.msg)),
            .nlmsg_type = m->nl80211.family_id,
            .nlmsg_flags = NLM_F_REQUEST,
            .nlmsg_seq = m->nl80211.seq_nr,
            .nlmsg_pid = nl_pid_value(),
        },

        .msg = {
            .genl = {
                .cmd = NL80211_CMD_GET_INTERFACE,
                .version = 1,
            },

            .ifindex = {
                .attr = {
                    .nla_type = NL80211_ATTR_IFINDEX,
                    .nla_len = sizeof(req.msg.ifindex),
                },

                .index = m->ifindex,
            },
        },
    };

    if (!send_nlmsg(m->genl_sock, &req, req.hdr.nlmsg_len)) {
        LOG_ERRNO("%s: failed to send netlink nl80211 get-inteface request",
                  m->iface);
        m->nl80211.seq_nr = 0;
        return false;
    }

    return true;
}

static bool
find_my_ifindex(struct module *mod, const struct ifinfomsg *msg, size_t len)
{
    struct private *m = mod->private;

    for (const struct rtattr *attr = IFLA_RTA(msg);
         RTA_OK(attr, len);
         attr = RTA_NEXT(attr, len))
    {
        switch (attr->rta_type) {
        case IFLA_IFNAME:
            if (strcmp((const char *)RTA_DATA(attr), m->iface) == 0) {
                LOG_INFO("%s: ifindex=%d", m->iface, msg->ifi_index);

                mtx_lock(&mod->lock);
                m->ifindex = msg->ifi_index;
                mtx_unlock(&mod->lock);

                send_nl80211_get_interface_request(m);
                return true;
            }

            return false;
        }
    }

    return false;
}

static void
handle_link(struct module *mod, uint16_t type,
            const struct ifinfomsg *msg, size_t len)
{
    assert(type == RTM_NEWLINK || type == RTM_DELLINK);

    struct private *m = mod->private;

    if (m->ifindex == -1) {
        /* We don't know our own ifindex yet. Let's see if we can find
         * it in the message */
        if (!find_my_ifindex(mod, msg, len)) {
            /* Nope, message wasn't for us (IFLA_IFNAME mismatch) */
            return;
        }
    }

    assert(m->ifindex >= 0);

    if (msg->ifi_index != m->ifindex) {
        /* Not for us */
        return;
    }

    bool update_bar = false;

    for (const struct rtattr *attr = IFLA_RTA(msg);
         RTA_OK(attr, len);
         attr = RTA_NEXT(attr, len))
    {
        switch (attr->rta_type) {
        case IFLA_OPERSTATE: {
            uint8_t operstate = *(const uint8_t *)RTA_DATA(attr);
            if (m->state == operstate)
                break;

            LOG_DBG("%s: IFLA_OPERSTATE: %hhu -> %hhu", m->iface, m->state, operstate);

            mtx_lock(&mod->lock);
            m->state = operstate;
            mtx_unlock(&mod->lock);
            update_bar = true;
            break;
        }

        case IFLA_CARRIER: {
            uint8_t carrier = *(const uint8_t *)RTA_DATA(attr);
            if (m->carrier == carrier)
                break;

            LOG_DBG("%s: IFLA_CARRIER: %hhu -> %hhu", m->iface, m->carrier, carrier);

            mtx_lock(&mod->lock);
            m->carrier = carrier;
            mtx_unlock(&mod->lock);
            update_bar = true;
            break;
        }

        case IFLA_ADDRESS: {
            if (RTA_PAYLOAD(attr) != 6)
                break;

            const uint8_t *mac = RTA_DATA(attr);
            if (memcmp(m->mac, mac, sizeof(m->mac)) == 0)
                break;

            LOG_DBG("%s: IFLA_ADDRESS: %02x:%02x:%02x:%02x:%02x:%02x",
                    m->iface,
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

            mtx_lock(&mod->lock);
            memcpy(m->mac, mac, sizeof(m->mac));
            mtx_unlock(&mod->lock);
            update_bar = true;
            break;
        }
        }
    }

    if (update_bar)
        mod->bar->refresh(mod->bar);
}

static void
handle_address(struct module *mod, uint16_t type,
               const struct ifaddrmsg *msg, size_t len)
{
    assert(type == RTM_NEWADDR || type == RTM_DELADDR);

    struct private *m = mod->private;

    assert(m->ifindex >= 0);

    if (msg->ifa_index != m->ifindex) {
        /* Not for us */
        return;
    }

    bool update_bar = false;

    for (const struct rtattr *attr = IFA_RTA(msg);
         RTA_OK(attr, len);
         attr = RTA_NEXT(attr, len))
    {
        switch (attr->rta_type) {
        case IFA_ADDRESS: {
            const void *raw_addr = RTA_DATA(attr);
            size_t addr_len = RTA_PAYLOAD(attr);

#if defined(LOG_ENABLE_DBG) && LOG_ENABLE_DBG
            char s[INET6_ADDRSTRLEN];
            inet_ntop(msg->ifa_family, raw_addr, s, sizeof(s));
#endif
            LOG_DBG("%s: IFA_ADDRESS (%s): %s", m->iface,
                    type == RTM_NEWADDR ? "add" : "del", s);

            mtx_lock(&mod->lock);

            if (type == RTM_DELADDR) {
                /* Find address in our list and remove it */
                tll_foreach(m->addrs, it) {
                    if (it->item.family != msg->ifa_family)
                        continue;

                    if (memcmp(&it->item.addr, raw_addr, addr_len) != 0)
                        continue;

                    tll_remove(m->addrs, it);
                    update_bar = true;
                    break;
                }
            } else {
                /* Append address to our list */
                struct af_addr a = {.family = msg->ifa_family};
                memcpy(&a.addr, raw_addr, addr_len);
                tll_push_back(m->addrs, a);
                update_bar = true;
            }

            mtx_unlock(&mod->lock);
            break;
        }
        }
    }

    if (update_bar)
        mod->bar->refresh(mod->bar);
}

static bool
foreach_nlattr(struct module *mod, const struct genlmsghdr *genl, size_t len,
               bool (*cb)(struct module *mod, uint16_t type, bool nested,
                          const void *payload, size_t len))
{
    const uint8_t *raw = (const uint8_t *)genl + GENL_HDRLEN;
    const uint8_t *end = (const uint8_t *)genl + len;

    for (const struct nlattr *attr = (const struct nlattr *)raw;
         raw < end;
         raw += NLA_ALIGN(attr->nla_len), attr = (const struct nlattr *)raw)
    {
        uint16_t type = attr->nla_type & NLA_TYPE_MASK;
        bool nested = (attr->nla_type & NLA_F_NESTED) != 0;;
        const void *payload = raw + NLA_HDRLEN;

        if (!cb(mod, type, nested, payload, attr->nla_len - NLA_HDRLEN))
            return false;
    }

    return true;
}

static bool
foreach_nlattr_nested(struct module *mod, const void *parent_payload, size_t len,
                      bool (*cb)(struct module *mod, uint16_t type,
                                 bool nested, const void *payload, size_t len,
                                 void *ctx),
                      void *ctx)
{
    const uint8_t *raw = parent_payload;
    const uint8_t *end = parent_payload + len;

    for (const struct nlattr *attr = (const struct nlattr *)raw;
         raw < end;
         raw += NLA_ALIGN(attr->nla_len), attr = (const struct nlattr *)raw)
    {
        uint16_t type = attr->nla_type & NLA_TYPE_MASK;
        bool nested = (attr->nla_type & NLA_F_NESTED) != 0;
        const void *payload = raw + NLA_HDRLEN;

        if (!cb(mod, type, nested, payload, attr->nla_len - NLA_HDRLEN, ctx))
            return false;
    }

    return true;
}

struct mcast_group {
    uint32_t id;
    char *name;
};

static bool
parse_mcast_group(struct module *mod, uint16_t type, bool nested,
                  const void *payload, size_t len, void *_ctx)
{
    struct private *m = mod->private;
    struct mcast_group *ctx = _ctx;

    switch (type) {
    case CTRL_ATTR_MCAST_GRP_ID: {
        ctx->id = *(uint32_t *)payload;
        break;
    }

    case CTRL_ATTR_MCAST_GRP_NAME: {
        free(ctx->name);
        ctx->name = strndup((const char *)payload, len);
        break;
    }

    default:
        LOG_WARN("%s: unrecognized GENL MCAST GRP attribute: "
                 "%hu%s (size: %zu bytes)", m->iface,
                 type, nested ? " (nested)" : "", len);
        break;
    }

    return true;
}

static bool
parse_mcast_groups(struct module *mod, uint16_t type, bool nested,
                   const void *payload, size_t len, void *_ctx)
{
    struct private *m = mod->private;

    struct mcast_group group = {0};
    foreach_nlattr_nested(mod, payload, len, &parse_mcast_group, &group);

    LOG_DBG("MCAST: %s -> %u", group.name, group.id);

    if (strcmp(group.name, NL80211_MULTICAST_GROUP_MLME) == 0) {
        int r = setsockopt(
            m->genl_sock, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
            &group.id, sizeof(int));

        if (r < 0)
            LOG_ERRNO("failed to joint the nl80211 MLME mcast group");
    }

    free(group.name);
    return true;
}

static bool
handle_genl_ctrl(struct module *mod, uint16_t type, bool nested,
                 const void *payload, size_t len)
{
    struct private *m = mod->private;

    switch (type) {
    case CTRL_ATTR_FAMILY_ID: {
        m->nl80211.family_id = *(const uint16_t *)payload;
        send_nl80211_get_interface_request(m);
        break;
    }

    case CTRL_ATTR_FAMILY_NAME:
        //LOG_INFO("NAME: %.*s (%zu bytes)", (int)len, (const char *)payload, len);
        break;

    case CTRL_ATTR_MCAST_GROUPS:
        foreach_nlattr_nested(mod, payload, len, &parse_mcast_groups, NULL);
        break;

    default:
        LOG_DBG("%s: unrecognized GENL CTRL attribute: "
                "%hu%s (size: %zu bytes)", m->iface,
                type, nested ? " (nested)" : "", len);
        break;
    }

    return true;
}

static bool
check_for_nl80211_ifindex(struct module *mod, uint16_t type, bool nested,
                          const void *payload, size_t len)
{
    struct private *m = mod->private;

    switch (type) {
    case NL80211_ATTR_IFINDEX:
        return *(uint32_t *)payload == m->ifindex;
    }

    return true;
}

static bool
nl80211_is_for_us(struct module *mod, const struct genlmsghdr *genl,
                   size_t msg_size)
{
    return foreach_nlattr(mod, genl, msg_size, &check_for_nl80211_ifindex);
}

static bool
handle_nl80211_new_interface(struct module *mod, uint16_t type, bool nested,
                             const void *payload, size_t len)
{
    struct private *m = mod->private;

    switch (type) {
    case NL80211_ATTR_IFINDEX:
        assert(*(uint32_t *)payload == m->ifindex);
        break;

    case NL80211_ATTR_SSID: {
        const char *ssid = payload;
        LOG_INFO("%s: SSID: %.*s (type=%hhu)", m->iface, (int)len, ssid, type);

        mtx_lock(&mod->lock);
        free(m->ssid);
        m->ssid = strndup(ssid, len);
        mtx_unlock(&mod->lock);

        mod->bar->refresh(mod->bar);
        break;
    }

    default:
        LOG_DBG("%s: unrecognized nl80211 attribute: "
                "type=%hu%s, len=%zu", m->iface,
                type, nested ? " (nested)" : "", len);
        break;
    }

    return true;
}

/*
 * Reads at least one (possibly more) message.
 *
 * On success, 'reply' will point to a malloc:ed buffer, to be freed
 * by the caller. 'len' is set to the size of the message (note that
 * the allocated size may actually be larger).
 *
 * Returns true on success, otherwise false
 */
static bool
netlink_receive_messages(int sock, void **reply, size_t *len)
{
    /* Use MSG_PEEK to find out how large buffer we need */
    const size_t chunk_sz = 1024;
    size_t sz = chunk_sz;
    *reply = malloc(sz);

    while (true) {
        ssize_t bytes = recvfrom(sock, *reply, sz, MSG_PEEK, NULL, NULL);
        if (bytes == -1) {
            LOG_ERRNO("failed to receive from netlink socket");
            free(*reply);
            return false;
        }

        if (bytes < sz)
            break;

        sz += chunk_sz;
        *reply = realloc(*reply, sz);
    }

    *len = recvfrom(sock, *reply, sz, 0, NULL, NULL);
    assert(*len >= 0);
    assert(*len < sz);
    return true;
}

static bool
parse_rt_reply(struct module *mod, const struct nlmsghdr *hdr, size_t len)
{
    struct private *m = mod->private;

    /* Process response */
    for (; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {
        switch (hdr->nlmsg_type) {
        case NLMSG_DONE:
            if (m->ifindex == -1) {
                LOG_ERR("%s: failed to find interface", m->iface);
                return false;
            }

            /* Request initial list of IPv4/6 addresses */
            if (m->get_addresses && m->ifindex != -1) {
                m->get_addresses = false;
                send_rt_request(m, RTM_GETADDR);
            }
            break;

        case RTM_NEWLINK:
        case RTM_DELLINK: {
            const struct ifinfomsg *msg = NLMSG_DATA(hdr);
            size_t msg_len = IFLA_PAYLOAD(hdr);

            handle_link(mod, hdr->nlmsg_type, msg, msg_len);
            break;
        }

        case RTM_NEWADDR:
        case RTM_DELADDR: {
            const struct ifaddrmsg *msg = NLMSG_DATA(hdr);
            size_t msg_len = IFA_PAYLOAD(hdr);

            handle_address(mod, hdr->nlmsg_type, msg, msg_len);
            break;
        }

        case NLMSG_ERROR:{
            const struct nlmsgerr *err = NLMSG_DATA(hdr);
            LOG_ERRNO_P(-err->error, "%s: netlink RT reply", m->iface);
            return false;
        }

        default:
            LOG_WARN(
                "%s: unrecognized netlink message type: 0x%x",
                m->iface, hdr->nlmsg_type);
            return false;
        }
    }

    return true;
}

static bool
parse_genl_reply(struct module *mod, const struct nlmsghdr *hdr, size_t len)
{
    struct private *m = mod->private;

    for (; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {
        if (hdr->nlmsg_seq == m->nl80211.seq_nr) {
            /* Current request is now considered complete */
            m->nl80211.seq_nr = 0;
        }

        if (hdr->nlmsg_type == GENL_ID_CTRL) {
            const struct genlmsghdr *genl = NLMSG_DATA(hdr);
            const size_t msg_size = NLMSG_PAYLOAD(hdr, 0);
            foreach_nlattr(mod, genl, msg_size, &handle_genl_ctrl);
        }

        else if (hdr->nlmsg_type == m->nl80211.family_id) {
            const struct genlmsghdr *genl = NLMSG_DATA(hdr);
            const size_t msg_size = NLMSG_PAYLOAD(hdr, 0);

            switch (genl->cmd) {
            case NL80211_CMD_NEW_INTERFACE:
                if (nl80211_is_for_us(mod, genl, msg_size)) {
                    LOG_DBG("%s: got interface information", m->iface);
                    foreach_nlattr(
                        mod, genl, msg_size, &handle_nl80211_new_interface);
                }
                break;

            case NL80211_CMD_CONNECT:
                /*
                 * Update SSID
                 *
                 * Unfortunately, the SSID doesn’t appear to be
                 * included in *any* of the notifications sent when
                 * associating, authenticating and connecting to a
                 * station.
                 *
                 * Thus, we need to explicitly request an update.
                 */
                if (nl80211_is_for_us(mod, genl, msg_size)) {
                    LOG_DBG("%s: connected, requesting interface information",
                            m->iface);
                    send_nl80211_get_interface_request(m);
                }
                break;

            case NL80211_CMD_DISCONNECT:
                if (nl80211_is_for_us(mod, genl, msg_size)) {
                    LOG_DBG("%s: disconnected, resetting SSID etc", m->iface);
                    mtx_lock(&mod->lock);
                    free(m->ssid);
                    m->ssid = NULL;
                    mtx_unlock(&mod->lock);
                }
                break;

            default:
                LOG_DBG("unrecognized nl80211 command: %hhu", genl->cmd);
                break;
            }
        }

        else if (hdr->nlmsg_type == NLMSG_ERROR) {
            const struct nlmsgerr *err = NLMSG_DATA(hdr);
            int nl_errno = -err->error;

            if (nl_errno == ENODEV)
                ; /* iface is not an nl80211 device */
            else if (nl_errno == ENOENT)
                ; /* iface down? */
            else
                LOG_ERRNO_P(nl_errno, "%s: nl80211 reply", m->iface);
        }

        else {
            LOG_WARN(
                "%s: unrecognized netlink message type: 0x%x",
                m->iface, hdr->nlmsg_type);
            return false;
        }
    }

    return true;
}

static int
run(struct module *mod)
{
    int ret = 1;
    struct private *m = mod->private;

    m->rt_sock = netlink_connect_rt();
    m->genl_sock = netlink_connect_genl();

    if (m->rt_sock < 0 || m->genl_sock < 0)
        goto out;

    if (!send_rt_request(m, RTM_GETLINK) ||
        !send_ctrl_get_family_request(m))
    {
        goto out;
    }

    /* Main loop */
    while (true) {
        struct pollfd fds[] = {
            {.fd = mod->abort_fd, .events = POLLIN},
            {.fd = m->rt_sock, .events = POLLIN},
            {.fd = m->genl_sock, .events = POLLIN},
        };

        poll(fds, 3, -1);

        if (fds[0].revents & (POLLIN | POLLHUP))
            break;

        if ((fds[1].revents & POLLHUP) ||
            (fds[2].revents & POLLHUP))
        {
            LOG_ERR("%s: disconnected from netlink socket", m->iface);
            break;
        }

        if (fds[1].revents & POLLIN) {
            /* Read one (or more) messages */
            void *reply;
            size_t len;
            if (!netlink_receive_messages(m->rt_sock, &reply, &len))
                break;

            /* Parse (and act upon) the received message(s) */
            if (!parse_rt_reply(mod, (const struct nlmsghdr *)reply, len)) {
                free(reply);
                break;
            }

            free(reply);
        }

        if (fds[2].revents & POLLIN) {
            /* Read one (or more) messages */
            void *reply;
            size_t len;
            if (!netlink_receive_messages(m->genl_sock, &reply, &len))
                break;

            if (!parse_genl_reply(mod, (const struct nlmsghdr *)reply, len)) {
                free(reply);
                break;
            }

            free(reply);
        }
    }

    ret = 0;

    out:
    if (m->rt_sock >= 0)
        close(m->rt_sock);
    if (m->genl_sock >= 0)
        close(m->genl_sock);
    m->rt_sock = m->genl_sock = -1;
    return ret;
}

static struct module *
network_new(const char *iface, struct particle *label)
{
    struct private *priv = calloc(1, sizeof(*priv));
    priv->iface = strdup(iface);
    priv->label = label;

    priv->genl_sock = -1;
    priv->rt_sock = -1;
    priv->nl80211.family_id = -1;
    priv->get_addresses = true;
    priv->ifindex = -1;
    priv->state = IF_OPER_DOWN;

    struct module *mod = module_common_new();
    mod->private = priv;
    mod->run = &run;
    mod->destroy = &destroy;
    mod->content = &content;
    mod->description = &description;
    return mod;
}

static struct module *
from_conf(const struct yml_node *node, struct conf_inherit inherited)
{
    const struct yml_node *name = yml_get_value(node, "name");
    const struct yml_node *content = yml_get_value(node, "content");

    return network_new(
        yml_value_as_string(name), conf_to_particle(content, inherited));
}

static bool
verify_conf(keychain_t *chain, const struct yml_node *node)
{
    static const struct attr_info attrs[] = {
        {"name", true, &conf_verify_string},
        MODULE_COMMON_ATTRS,
    };

    return conf_verify_dict(chain, node, attrs);
}

const struct module_iface module_network_iface = {
    .verify_conf = &verify_conf,
    .from_conf = &from_conf,
};

#if defined(CORE_PLUGINS_AS_SHARED_LIBRARIES)
extern const struct module_iface iface __attribute__((weak, alias("module_network_iface")));
#endif
