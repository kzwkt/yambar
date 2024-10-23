#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <poll.h>

#include <fcntl.h>
#include <sys/stat.h>

#include <libudev.h>
#include <tllist.h>

#define LOG_MODULE "battery"
#define LOG_ENABLE_DBG 0
#include "../bar/bar.h"
#include "../config-verify.h"
#include "../config.h"
#include "../log.h"
#include "../plugin.h"

#define max(x, y) ((x) > (y) ? (x) : (y))

static const long min_poll_interval = 250;
static const long default_poll_interval = 60 * 1000;
static const long one_sec_in_ns = 1000000000;

enum state { STATE_FULL, STATE_NOTCHARGING, STATE_CHARGING, STATE_DISCHARGING, STATE_UNKNOWN };

struct current_state {
    long ema;
    long current;
    struct timespec time;
};

struct private
{
    struct particle *label;

    long poll_interval;
    int battery_scale;
    long smoothing_scale;
    char *battery;
    char *manufacturer;
    char *model;
    long energy_full_design;
    long energy_full;
    long charge_full_design;
    long charge_full;

    enum state state;
    long capacity;
    long energy;
    long power;
    long charge;
    struct current_state ema_current;
    long time_to_empty;
    long time_to_full;
};

static int64_t
difftimespec_ns(const struct timespec after, const struct timespec before)
{
    return ((int64_t)after.tv_sec - (int64_t)before.tv_sec) * (int64_t)one_sec_in_ns
           + ((int64_t)after.tv_nsec - (int64_t)before.tv_nsec);
}

// Linear Exponential Moving Average (unevenly spaced time series)
// http://www.eckner.com/papers/Algorithms%20for%20Unevenly%20Spaced%20Time%20Series.pdf
// Adapted from: https://github.com/andreas50/utsAlgorithms/blob/master/ema.c
static void
ema_linear(struct current_state *state, struct current_state curr, long tau)
{
    double w, w2, tmp;

    if (state->current == -1) {
        *state = curr;
        return;
    }

    long time = difftimespec_ns(curr.time, state->time);
    tmp = time / (double)tau;
    w = exp(-tmp);
    if (tmp > 1e-6) {
        w2 = (1 - w) / tmp;
    } else {
        // Use taylor expansion for numerical stability
        w2 = 1 - tmp / 2 + tmp * tmp / 6 - tmp * tmp * tmp / 24;
    }

    double ema = state->ema * w + curr.current * (1 - w2) + state->current * (w2 - w);

    state->ema = ema;
    state->current = curr.current;
    state->time = curr.time;

    LOG_DBG("ema current: %ld", (long)ema);
}

static void
timespec_sub(const struct timespec *a, const struct timespec *b, struct timespec *res)
{

    res->tv_sec = a->tv_sec - b->tv_sec;
    res->tv_nsec = a->tv_nsec - b->tv_nsec;

    /* tv_nsec may be negative */
    if (res->tv_nsec < 0) {
        res->tv_sec--;
        res->tv_nsec += one_sec_in_ns;
    }
}

static void
destroy(struct module *mod)
{
    struct private *m = mod->private;
    free(m->battery);
    free(m->manufacturer);
    free(m->model);

    m->label->destroy(m->label);

    free(m);
    module_default_destroy(mod);
}

static const char *
description(const struct module *mod)
{
    static char desc[32];
    const struct private *m = mod->private;
    snprintf(desc, sizeof(desc), "bat(%s)", m->battery);
    return desc;
}

static struct exposable *
content(struct module *mod)
{
    const struct private *m = mod->private;

    mtx_lock(&mod->lock);

    assert(m->state == STATE_FULL || m->state == STATE_NOTCHARGING || m->state == STATE_CHARGING
           || m->state == STATE_DISCHARGING || m->state == STATE_UNKNOWN);

    unsigned long hours;
    unsigned long minutes;

    if (m->time_to_empty > 0) {
        minutes = m->time_to_empty / 60;
        hours = minutes / 60;
        minutes = minutes % 60;
    } else if (m->time_to_full > 0) {
        minutes = m->time_to_full / 60;
        hours = minutes / 60;
        minutes = minutes % 60;
    } else if (m->energy_full >= 0 && m->charge && m->power >= 0) {
        unsigned long energy = m->state == STATE_CHARGING ? m->energy_full - m->energy : m->energy;

        double hours_as_float;
        if (m->state == STATE_FULL || m->state == STATE_NOTCHARGING)
            hours_as_float = 0.0;
        else if (m->power > 0)
            hours_as_float = (double)energy / m->power;
        else
            hours_as_float = 99.0;

        hours = hours_as_float;
        minutes = (hours_as_float - (double)hours) * 60;
    } else if (m->charge_full >= 0 && m->charge >= 0 && m->ema_current.current >= 0) {
        unsigned long charge = m->state == STATE_CHARGING ? m->charge_full - m->charge : m->charge;

        double hours_as_float;
        if (m->state == STATE_FULL || m->state == STATE_NOTCHARGING)
            hours_as_float = 0.0;
        else if (m->ema_current.current > 0)
            hours_as_float = (double)charge / m->ema_current.current;
        else
            hours_as_float = 99.0;

        hours = hours_as_float;
        minutes = (hours_as_float - (double)hours) * 60;
    } else {
        hours = 99;
        minutes = 0;
    }

    char estimate[64];
    snprintf(estimate, sizeof(estimate), "%02lu:%02lu", hours, minutes);

    struct tag_set tags = {
        .tags = (struct tag *[]){
            tag_new_string(mod, "name", m->battery),
            tag_new_string(mod, "manufacturer", m->manufacturer),
            tag_new_string(mod, "model", m->model),
            tag_new_string(mod, "state",
                           m->state == STATE_FULL ? "full" :
                           m->state == STATE_NOTCHARGING ? "not charging" :
                           m->state == STATE_CHARGING ? "charging" :
                           m->state == STATE_DISCHARGING ? "discharging" :
                           "unknown"),
            tag_new_int_range(mod, "capacity", m->capacity, 0, 100),
            tag_new_string(mod, "estimate", estimate),
        },
        .count = 6,
    };

    mtx_unlock(&mod->lock);

    struct exposable *exposable = m->label->instantiate(m->label, &tags);

    tag_set_destroy(&tags);
    return exposable;
}

static const char *
readline_from_fd(int fd, size_t sz, char buf[static sz])
{
    ssize_t bytes = read(fd, buf, sz - 1);
    lseek(fd, 0, SEEK_SET);

    if (bytes < 0) {
        LOG_WARN("failed to read from FD=%d", fd);
        return NULL;
    }

    buf[bytes] = '\0';
    for (ssize_t i = bytes - 1; i >= 0 && buf[i] == '\n'; bytes--)
        buf[i] = '\0';

    return buf;
}

static long
readint_from_fd(int fd)
{
    char buf[512];
    const char *s = readline_from_fd(fd, sizeof(buf), buf);
    if (s == NULL)
        return 0;

    long ret;
    int r = sscanf(s, "%ld", &ret);
    if (r != 1) {
        LOG_WARN("failed to convert \"%s\" to an integer", s);
        return 0;
    }

    return ret;
}

static bool
initialize(struct private *m)
{
    char line_buf[512];

    int pw_fd = open("/sys/class/power_supply", O_RDONLY | O_CLOEXEC);
    if (pw_fd < 0) {
        LOG_ERRNO("/sys/class/power_supply");
        return false;
    }

    int base_dir_fd = openat(pw_fd, m->battery, O_RDONLY | O_CLOEXEC);
    close(pw_fd);

    if (base_dir_fd < 0) {
        LOG_ERRNO("/sys/class/power_supply/%s", m->battery);
        return false;
    }

    {
        int fd = openat(base_dir_fd, "manufacturer", O_RDONLY | O_CLOEXEC);
        if (fd == -1) {
            LOG_WARN("/sys/class/power_supply/%s/manufacturer: %s", m->battery, strerror(errno));
            m->manufacturer = NULL;
        } else {
            m->manufacturer = strdup(readline_from_fd(fd, sizeof(line_buf), line_buf));
            close(fd);
        }
    }

    {
        int fd = openat(base_dir_fd, "model_name", O_RDONLY | O_CLOEXEC);
        if (fd == -1) {
            LOG_WARN("/sys/class/power_supply/%s/model_name: %s", m->battery, strerror(errno));
            m->model = NULL;
        } else {
            m->model = strdup(readline_from_fd(fd, sizeof(line_buf), line_buf));
            close(fd);
        }
    }

    if (faccessat(base_dir_fd, "energy_full_design", O_RDONLY, 0) == 0
        && faccessat(base_dir_fd, "energy_full", O_RDONLY, 0) == 0) {
        {
            int fd = openat(base_dir_fd, "energy_full_design", O_RDONLY | O_CLOEXEC);
            if (fd == -1) {
                LOG_ERRNO("/sys/class/power_supply/%s/energy_full_design", m->battery);
                goto err;
            }

            m->energy_full_design = readint_from_fd(fd);
            close(fd);
        }

        {
            int fd = openat(base_dir_fd, "energy_full", O_RDONLY | O_CLOEXEC);
            if (fd == -1) {
                LOG_ERRNO("/sys/class/power_supply/%s/energy_full", m->battery);
                goto err;
            }

            m->energy_full = readint_from_fd(fd);
            close(fd);
        }
    } else {
        m->energy_full = m->energy_full_design = -1;
    }

    if (faccessat(base_dir_fd, "charge_full_design", O_RDONLY, 0) == 0
        && faccessat(base_dir_fd, "charge_full", O_RDONLY, 0) == 0) {
        {
            int fd = openat(base_dir_fd, "charge_full_design", O_RDONLY | O_CLOEXEC);
            if (fd == -1) {
                LOG_ERRNO("/sys/class/power_supply/%s/charge_full_design", m->battery);
                goto err;
            }

            m->charge_full_design = readint_from_fd(fd) / m->battery_scale;
            close(fd);
        }

        {
            int fd = openat(base_dir_fd, "charge_full", O_RDONLY | O_CLOEXEC);
            if (fd == -1) {
                LOG_ERRNO("/sys/class/power_supply/%s/charge_full", m->battery);
                goto err;
            }

            m->charge_full = readint_from_fd(fd) / m->battery_scale;
            close(fd);
        }
    } else {
        m->charge_full = m->charge_full_design = -1;
    }

    close(base_dir_fd);
    return true;

err:
    close(base_dir_fd);
    return false;
}

static bool
update_status(struct module *mod)
{
    struct private *m = mod->private;

    int pw_fd = open("/sys/class/power_supply", O_RDONLY | O_CLOEXEC);
    if (pw_fd < 0) {
        LOG_ERRNO("/sys/class/power_supply");
        return false;
    }

    int base_dir_fd = openat(pw_fd, m->battery, O_RDONLY | O_CLOEXEC);
    close(pw_fd);

    if (base_dir_fd < 0) {
        LOG_ERRNO("/sys/class/power_supply/%s", m->battery);
        return false;
    }

    int status_fd = openat(base_dir_fd, "status", O_RDONLY | O_CLOEXEC);
    if (status_fd < 0) {
        LOG_ERRNO("/sys/class/power_supply/%s/status", m->battery);
        close(base_dir_fd);
        return false;
    }

    int capacity_fd = openat(base_dir_fd, "capacity", O_RDONLY | O_CLOEXEC);
    if (capacity_fd < 0) {
        LOG_ERRNO("/sys/class/power_supply/%s/capacity", m->battery);
        close(status_fd);
        close(base_dir_fd);
        return false;
    }

    int energy_fd = openat(base_dir_fd, "energy_now", O_RDONLY | O_CLOEXEC);
    int power_fd = openat(base_dir_fd, "power_now", O_RDONLY | O_CLOEXEC);
    int charge_fd = openat(base_dir_fd, "charge_now", O_RDONLY | O_CLOEXEC);
    int current_fd = openat(base_dir_fd, "current_now", O_RDONLY | O_CLOEXEC);
    int time_to_empty_fd = openat(base_dir_fd, "time_to_empty_now", O_RDONLY | O_CLOEXEC);
    int time_to_full_fd = openat(base_dir_fd, "time_to_full_now", O_RDONLY | O_CLOEXEC);

    long capacity = readint_from_fd(capacity_fd);
    long energy = energy_fd >= 0 ? readint_from_fd(energy_fd) : -1;
    long power = power_fd >= 0 ? readint_from_fd(power_fd) : -1;
    long charge = charge_fd >= 0 ? readint_from_fd(charge_fd) : -1;
    long current = current_fd >= 0 ? readint_from_fd(current_fd) : -1;
    long time_to_empty = time_to_empty_fd >= 0 ? readint_from_fd(time_to_empty_fd) : -1;
    long time_to_full = time_to_full_fd >= 0 ? readint_from_fd(time_to_full_fd) : -1;

    if (charge >= -1) {
        charge /= m->battery_scale;
    }

    char buf[512];
    const char *status = readline_from_fd(status_fd, sizeof(buf), buf);

    if (status_fd >= 0)
        close(status_fd);
    if (capacity_fd >= 0)
        close(capacity_fd);
    if (energy_fd >= 0)
        close(energy_fd);
    if (power_fd >= 0)
        close(power_fd);
    if (charge_fd >= 0)
        close(charge_fd);
    if (current_fd >= 0)
        close(current_fd);
    if (time_to_empty_fd >= 0)
        close(time_to_empty_fd);
    if (time_to_full_fd >= 0)
        close(time_to_full_fd);
    if (base_dir_fd >= 0)
        close(base_dir_fd);

    enum state state;

    if (status == NULL) {
        LOG_WARN("failed to read battery state");
        state = STATE_UNKNOWN;
    } else if (strcmp(status, "Full") == 0)
        state = STATE_FULL;
    else if (strcmp(status, "Not charging") == 0)
        state = STATE_NOTCHARGING;
    else if (strcmp(status, "Charging") == 0)
        state = STATE_CHARGING;
    else if (strcmp(status, "Discharging") == 0)
        state = STATE_DISCHARGING;
    else if (strcmp(status, "Unknown") == 0)
        state = STATE_UNKNOWN;
    else {
        LOG_ERR("unrecognized battery state: %s", status);
        state = STATE_UNKNOWN;
    }

    LOG_DBG("capacity: %ld, energy: %ld, power: %ld, charge=%ld, current=%ld, "
            "time-to-empty: %ld, time-to-full: %ld",
            capacity, energy, power, charge, current, time_to_empty, time_to_full);

    mtx_lock(&mod->lock);
    if (m->state != state) {
        m->ema_current = (struct current_state){-1, 0, (struct timespec){0, 0}};
    }
    m->state = state;
    m->capacity = capacity;
    m->energy = energy;
    m->power = power;
    m->charge = charge;
    if (current != -1) {
        struct timespec t;
        clock_gettime(CLOCK_MONOTONIC, &t);
        ema_linear(&m->ema_current, (struct current_state){current, current, t}, m->smoothing_scale);
    }
    m->time_to_empty = time_to_empty;
    m->time_to_full = time_to_full;
    mtx_unlock(&mod->lock);
    return true;
}

static int
run(struct module *mod)
{
    const struct bar *bar = mod->bar;
    struct private *m = mod->private;

    if (!initialize(m))
        return -1;

    LOG_INFO("%s: %s %s (at %.1f%% of original capacity)", m->battery, m->manufacturer, m->model,
             (m->energy_full > 0   ? 100.0 * m->energy_full / m->energy_full_design
              : m->charge_full > 0 ? 100.0 * m->charge_full / m->charge_full_design
                                   : 0.0));

    int ret = 1;

    struct udev *udev = udev_new();
    struct udev_monitor *mon = udev_monitor_new_from_netlink(udev, "udev");

    if (udev == NULL || mon == NULL)
        goto out;

    udev_monitor_filter_add_match_subsystem_devtype(mon, "power_supply", NULL);
    udev_monitor_enable_receiving(mon);

    if (!update_status(mod))
        goto out;

    bar->refresh(bar);

    int timeout_left_ms = m->poll_interval;

    while (true) {
        struct pollfd fds[] = {
            {.fd = mod->abort_fd, .events = POLLIN},
            {.fd = udev_monitor_get_fd(mon), .events = POLLIN},
        };

        int timeout = m->poll_interval > 0 ? timeout_left_ms : -1;

        struct timespec time_before_poll;
        if (clock_gettime(CLOCK_BOOTTIME, &time_before_poll) < 0) {
            LOG_ERRNO("failed to get current time");
            break;
        }

        const int poll_ret = poll(fds, sizeof(fds) / sizeof(fds[0]), timeout);

        if (poll_ret < 0) {
            if (errno == EINTR)
                continue;

            LOG_ERRNO("failed to poll");
            break;
        }

        if (fds[0].revents & POLLIN) {
            ret = 0;
            break;
        }

        bool udev_for_us = false;

        if (fds[1].revents & POLLIN) {
            struct udev_device *dev = udev_monitor_receive_device(mon);
            if (dev != NULL) {
                const char *sysname = udev_device_get_sysname(dev);
                udev_for_us = sysname != NULL && strcmp(sysname, m->battery) == 0;

                if (!udev_for_us) {
                    LOG_DBG("udev notification not for us (%s != %s)", m->battery,
                            sysname != sysname ? sysname : "NULL");
                } else
                    LOG_DBG("triggering update due to udev notification");

                udev_device_unref(dev);
            }
        }

        if (udev_for_us || poll_ret == 0) {
            if (update_status(mod))
                bar->refresh(bar);
        }

        if (poll_ret == 0 || udev_for_us) {
            LOG_DBG("resetting timeout-left to %ldms", m->poll_interval);
            timeout_left_ms = m->poll_interval;
        } else {
            struct timespec time_after_poll;
            if (clock_gettime(CLOCK_BOOTTIME, &time_after_poll) < 0) {
                LOG_ERRNO("failed to get current time");
                break;
            }

            struct timespec timeout_consumed;
            timespec_sub(&time_after_poll, &time_before_poll, &timeout_consumed);

            const int timeout_consumed_ms = timeout_consumed.tv_sec * 1000 + timeout_consumed.tv_nsec / 1000000;

            LOG_DBG("timeout-left before: %dms, consumed: %dms, updated: %dms", timeout_left_ms, timeout_consumed_ms,
                    max(timeout_left_ms - timeout_consumed_ms, 0));

            timeout_left_ms -= timeout_consumed_ms;
            if (timeout_left_ms < 0)
                timeout_left_ms = 0;
        }
    }

out:
    if (mon != NULL)
        udev_monitor_unref(mon);
    if (udev != NULL)
        udev_unref(udev);
    return ret;
}

static struct module *
battery_new(const char *battery, struct particle *label, long poll_interval_msecs, int battery_scale,
            long smoothing_secs)
{
    struct private *m = calloc(1, sizeof(*m));
    m->label = label;
    m->poll_interval = poll_interval_msecs;
    m->battery_scale = battery_scale;
    m->smoothing_scale = smoothing_secs * one_sec_in_ns;
    m->battery = strdup(battery);
    m->state = STATE_UNKNOWN;
    m->ema_current = (struct current_state){-1, 0, (struct timespec){0, 0}};

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
    const struct yml_node *name = yml_get_value(node, "name");
    const struct yml_node *poll_interval = yml_get_value(node, "poll-interval");
    const struct yml_node *battery_scale = yml_get_value(node, "battery-scale");
    const struct yml_node *smoothing_secs = yml_get_value(node, "smoothing-secs");

    return battery_new(yml_value_as_string(name), conf_to_particle(c, inherited),
                       (poll_interval != NULL ? yml_value_as_int(poll_interval) : default_poll_interval),
                       (battery_scale != NULL ? yml_value_as_int(battery_scale) : 1),
                       (smoothing_secs != NULL ? yml_value_as_int(smoothing_secs) : 100));
}

static bool
conf_verify_poll_interval(keychain_t *chain, const struct yml_node *node)
{
    if (!conf_verify_unsigned(chain, node))
        return false;

    const long value = yml_value_as_int(node);

    if (value != 0 && value < min_poll_interval) {
        LOG_ERR("%s: interval value cannot be less than %ldms", conf_err_prefix(chain, node), min_poll_interval);
        return false;
    }

    return true;
}

static bool
verify_conf(keychain_t *chain, const struct yml_node *node)
{
    static const struct attr_info attrs[] = {
        {"name", true, &conf_verify_string},
        {"poll-interval", false, &conf_verify_poll_interval},
        {"battery-scale", false, &conf_verify_unsigned},
        {"smoothing-secs", false, &conf_verify_unsigned},
        MODULE_COMMON_ATTRS,
    };

    return conf_verify_dict(chain, node, attrs);
}

const struct module_iface module_battery_iface = {
    .verify_conf = &verify_conf,
    .from_conf = &from_conf,
};

#if defined(CORE_PLUGINS_AS_SHARED_LIBRARIES)
extern const struct module_iface iface __attribute__((weak, alias("module_battery_iface")));
#endif
