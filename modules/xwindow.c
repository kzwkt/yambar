#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <unistd.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>

#include <xcb/xcb.h>
#include <xcb/xcb_aux.h>
#include <xcb/xcb_event.h>

#define LOG_MODULE "xwindow"
#include "../bar/bar.h"
#include "../config-verify.h"
#include "../config.h"
#include "../log.h"
#include "../plugin.h"
#include "../xcb.h"

struct private
{
    /* Accessed from bar thread only */
    struct particle *label;

    /* Accessed from both our thread, and the bar thread */
    char *application;
    char *title;

    /* Accessed from our thread only */
    xcb_connection_t *conn;
    xcb_window_t root_win;
    xcb_window_t monitor_win;
    xcb_window_t active_win;
};

static const char *
description(const struct module *mod)
{
    return "xwindow";
}

static void
update_active_window(struct private *m)
{
    if (m->active_win != 0) {
        xcb_void_cookie_t c = xcb_change_window_attributes_checked(m->conn, m->active_win, XCB_CW_EVENT_MASK,
                                                                   (const uint32_t[]){XCB_EVENT_MASK_NO_EVENT});

        xcb_generic_error_t *e = xcb_request_check(m->conn, c);
        if (e != NULL) {
            LOG_DBG("failed to de-register events on previous active window: %s", xcb_error(e));
            free(e);
        }

        m->active_win = 0;
    }

    xcb_get_property_cookie_t c = xcb_get_property(m->conn, 0, m->root_win, _NET_ACTIVE_WINDOW, XCB_ATOM_WINDOW, 0, 32);

    xcb_generic_error_t *e;
    xcb_get_property_reply_t *r = xcb_get_property_reply(m->conn, c, &e);

    if (e != NULL) {
        LOG_ERR("failed to get active window ID: %s", xcb_error(e));
        free(e);
        free(r);
        return;
    }

    if (xcb_get_property_value_length(r) != sizeof(m->active_win)) {
        free(r);
        return;
    }

    assert(sizeof(m->active_win) == xcb_get_property_value_length(r));
    memcpy(&m->active_win, xcb_get_property_value(r), sizeof(m->active_win));
    free(r);

    if (m->active_win != 0) {
        xcb_change_window_attributes(m->conn, m->active_win, XCB_CW_EVENT_MASK,
                                     (const uint32_t[]){XCB_EVENT_MASK_PROPERTY_CHANGE});
    }
}

static void
update_application(struct module *mod)
{
    struct private *m = mod->private;

    mtx_lock(&mod->lock);
    free(m->application);
    m->application = NULL;
    mtx_unlock(&mod->lock);

    if (m->active_win == 0)
        return;

    xcb_get_property_cookie_t c = xcb_get_property(m->conn, 0, m->active_win, _NET_WM_PID, XCB_ATOM_CARDINAL, 0, 32);

    xcb_generic_error_t *e;
    xcb_get_property_reply_t *r = xcb_get_property_reply(m->conn, c, &e);

    if (e != NULL) {
        LOG_ERR("failed to get _NET_WM_PID: %s", xcb_error(e));
        free(e);
        free(r);
        return;
    }

    if (xcb_get_property_value_length(r) == 0) {
        free(r);
        return;
    }

    uint32_t pid;
    if (xcb_get_property_value_length(r) != sizeof(pid)) {
        free(r);
        return;
    }

    memcpy(&pid, xcb_get_property_value(r), sizeof(pid));
    free(r);

    char path[1024];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    int fd = open(path, O_RDONLY);
    if (fd == -1)
        return;

    char cmd[1024] = {0};
    ssize_t bytes = read(fd, cmd, sizeof(cmd) - 1);
    close(fd);

    if (bytes == -1)
        return;

    mtx_lock(&mod->lock);
    m->application = strdup(basename(cmd));
    mtx_unlock(&mod->lock);
}

static void
update_title(struct module *mod)
{
    struct private *m = mod->private;

    mtx_lock(&mod->lock);
    free(m->title);
    m->title = NULL;
    mtx_unlock(&mod->lock);

    if (m->active_win == 0)
        return;

    xcb_get_property_cookie_t c1
        = xcb_get_property(m->conn, 0, m->active_win, _NET_WM_VISIBLE_NAME, UTF8_STRING, 0, 1000);
    xcb_get_property_cookie_t c2 = xcb_get_property(m->conn, 0, m->active_win, _NET_WM_NAME, UTF8_STRING, 0, 1000);
    xcb_get_property_cookie_t c3
        = xcb_get_property(m->conn, 0, m->active_win, XCB_ATOM_WM_NAME, XCB_ATOM_STRING, 0, 1000);

    xcb_generic_error_t *e1, *e2, *e3;
    xcb_get_property_reply_t *r1 = xcb_get_property_reply(m->conn, c1, &e1);
    xcb_get_property_reply_t *r2 = xcb_get_property_reply(m->conn, c2, &e2);
    xcb_get_property_reply_t *r3 = xcb_get_property_reply(m->conn, c3, &e3);

    const char *title;
    int title_len;

    if (e1 == NULL && xcb_get_property_value_length(r1) > 0) {
        title = xcb_get_property_value(r1);
        title_len = xcb_get_property_value_length(r1);
    } else if (e2 == NULL && xcb_get_property_value_length(r2) > 0) {
        title = xcb_get_property_value(r2);
        title_len = xcb_get_property_value_length(r2);
    } else if (e3 == NULL && xcb_get_property_value_length(r3) > 0) {
        title = xcb_get_property_value(r3);
        title_len = xcb_get_property_value_length(r3);
    } else {
        title = NULL;
        title_len = 0;
    }

    if (title_len > 0) {
        mtx_lock(&mod->lock);
        m->title = malloc(title_len + 1);
        memcpy(m->title, title, title_len);
        m->title[title_len] = '\0';
        mtx_unlock(&mod->lock);
    }

    free(e1);
    free(e2);
    free(e3);
    free(r1);
    free(r2);
    free(r3);
}

static int
run(struct module *mod)
{
    struct private *m = mod->private;

    int default_screen;
    m->conn = xcb_connect(NULL, &default_screen);
    if (xcb_connection_has_error(m->conn) > 0) {
        LOG_ERR("failed to connect to X");
        xcb_disconnect(m->conn);
        return 1;
    }

    xcb_screen_t *screen = xcb_aux_get_screen(m->conn, default_screen);
    m->root_win = screen->root;

    /* Need a window(?) to be able to process events */
    m->monitor_win = xcb_generate_id(m->conn);
    xcb_create_window(m->conn, screen->root_depth, m->monitor_win, screen->root, -1, -1, 1, 1, 0,
                      XCB_WINDOW_CLASS_INPUT_OUTPUT, screen->root_visual, XCB_CW_OVERRIDE_REDIRECT,
                      (const uint32_t[]){1});

    xcb_map_window(m->conn, m->monitor_win);

    /* Register for property changes on root window. This allows us to
     * catch e.g. window switches etc */
    xcb_change_window_attributes(m->conn, screen->root, XCB_CW_EVENT_MASK,
                                 (const uint32_t[]){XCB_EVENT_MASK_PROPERTY_CHANGE});

    xcb_flush(m->conn);

    update_active_window(m);
    update_application(mod);
    update_title(mod);
    mod->bar->refresh(mod->bar);

    int ret = 1;

    int xcb_fd = xcb_get_file_descriptor(m->conn);
    while (true) {
        struct pollfd fds[] = {{.fd = mod->abort_fd, .events = POLLIN}, {.fd = xcb_fd, .events = POLLIN}};
        if (poll(fds, sizeof(fds) / sizeof(fds[0]), -1) < 0) {
            if (errno == EINTR)
                continue;

            LOG_ERRNO("failed to poll");
            break;
        }

        if (fds[0].revents & POLLIN) {
            ret = 0;
            break;
        }

        for (xcb_generic_event_t *_e = xcb_wait_for_event(m->conn); _e != NULL; _e = xcb_poll_for_event(m->conn)) {
            switch (XCB_EVENT_RESPONSE_TYPE(_e)) {
            case 0:
                LOG_ERR("XCB: %s", xcb_error((const xcb_generic_error_t *)_e));
                break;

            case XCB_PROPERTY_NOTIFY: {
                xcb_property_notify_event_t *e = (xcb_property_notify_event_t *)_e;
                if (e->atom == _NET_ACTIVE_WINDOW || e->atom == _NET_CURRENT_DESKTOP) {
                    /* Active desktop and/or window changed */
                    update_active_window(m);
                    update_application(mod);
                    update_title(mod);
                    mod->bar->refresh(mod->bar);
                } else if (e->atom == _NET_WM_VISIBLE_NAME || e->atom == _NET_WM_NAME || e->atom == XCB_ATOM_WM_NAME) {
                    assert(e->window == m->active_win);
                    update_title(mod);
                    mod->bar->refresh(mod->bar);
                }
                break;
            }
            }

            free(_e);
        }
    }

    xcb_destroy_window(m->conn, m->monitor_win);
    xcb_disconnect(m->conn);
    return ret;
}

static struct exposable *
content(struct module *mod)
{
    struct private *m = mod->private;

    mtx_lock(&mod->lock);
    struct tag_set tags = {
        .tags = (struct tag *[]){
            tag_new_string(mod, "application", m->application),
            tag_new_string(mod, "title", m->title),
        },
        .count = 2,
    };
    mtx_unlock(&mod->lock);

    struct exposable *exposable = m->label->instantiate(m->label, &tags);

    tag_set_destroy(&tags);
    return exposable;
}

static void
destroy(struct module *mod)
{
    struct private *m = mod->private;
    m->label->destroy(m->label);
    free(m->application);
    free(m->title);
    free(m);
    module_default_destroy(mod);
}

static struct module *
xwindow_new(struct particle *label)
{
    struct private *m = calloc(1, sizeof(*m));
    m->label = label;

    struct module *mod = module_common_new();
    mod->private = m;
    mod->run = &run;
    mod->destroy = &destroy;
    mod->content = &content;
    mod->description = &description;
    return mod;
}

static struct module *
from_conf(const struct yml_node *node, struct conf_inherit inherited)
{
    const struct yml_node *c = yml_get_value(node, "content");
    return xwindow_new(conf_to_particle(c, inherited));
}

static bool
verify_conf(keychain_t *chain, const struct yml_node *node)
{
    static const struct attr_info attrs[] = {
        MODULE_COMMON_ATTRS,
    };

    return conf_verify_dict(chain, node, attrs);
}

const struct module_iface module_xwindow_iface = {
    .verify_conf = &verify_conf,
    .from_conf = &from_conf,
};

#if defined(CORE_PLUGINS_AS_SHARED_LIBRARIES)
extern const struct module_iface iface __attribute__((weak, alias("module_xwindow_iface")));
#endif
