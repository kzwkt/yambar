#include <errno.h>
#include <json-c/json.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#define LOG_MODULE "niri-language"
#define LOG_ENABLE_DBG 0
#include "niri-common.h"

#include "../log.h"
#include "../particles/dynlist.h"
#include "../plugin.h"

struct private
{
    struct particle *label;
    struct niri_socket *niri;
};

static void
destroy(struct module *module)
{
    struct private *private = module->private;
    private->label->destroy(private->label);

    free(private);

    module_default_destroy(module);
}

static const char *
description(const struct module *module)
{
    return "niri-lang";
}

static struct exposable *
content(struct module *module)
{
    const struct private *private = module->private;

    if (private->niri == NULL)
        return dynlist_exposable_new(&((struct exposable *){0}), 0, 0, 0);

    mtx_lock(&module->lock);
    mtx_lock(&private->niri->mtx);

    char *name = "???";
    size_t i = 0;
    tll_foreach(private->niri->keyboard_layouts, it)
    {
        if (i++ == private->niri->keyboard_layout_index)
            name = it->item;
    }

    struct tag_set tags = {
        .tags = (struct tag *[]){tag_new_string(module, "language", name)},
        .count = 1,
    };

    struct exposable *exposable = private->label->instantiate(private->label, &tags);
    tag_set_destroy(&tags);
    mtx_unlock(&private->niri->mtx);
    mtx_unlock(&module->lock);
    return exposable;
}

static int
run(struct module *module)
{
    struct private *private = module->private;

    /* Ugly, but I didn't find better way for waiting
     * the monitor's name to be set */
    char const *monitor;
    do {
        monitor = module->bar->output_name(module->bar);
        usleep(50);
    } while (monitor == NULL);

    private->niri = niri_socket_open(monitor);
    if (private->niri == NULL)
        return 1;

    int fd = niri_socket_subscribe(keyboard_layouts_changed | keyboard_layouts_switched);
    if (fd == -1) {
        niri_socket_close();
        return 1;
    }

    module->bar->refresh(module->bar);

    while (true) {
        struct pollfd fds[] = {
            (struct pollfd){.fd = module->abort_fd, .events = POLLIN},
            (struct pollfd){.fd = fd, .events = POLLIN},
        };

        if (poll(fds, sizeof(fds) / sizeof(fds[0]), -1) == -1) {
            if (errno == EINTR)
                continue;

            LOG_ERRNO("failed to poll");
            break;
        }

        if (fds[0].revents & POLLIN)
            break;

        if (read(fds[1].fd, &(uint64_t){0}, sizeof(uint64_t)) == -1)
            LOG_ERRNO("failed to read from eventfd");

        module->bar->refresh(module->bar);
    }

    niri_socket_close();
    return 0;
}

static struct module *
niri_language_new(struct particle *label)
{
    struct private *private = calloc(1, sizeof(struct private));
    private->label = label;

    struct module *module = module_common_new();
    module->private = private;
    module->run = &run;
    module->destroy = &destroy;
    module->content = &content;
    module->description = &description;

    return module;
}

static struct module *
from_conf(struct yml_node const *node, struct conf_inherit inherited)
{
    struct yml_node const *content = yml_get_value(node, "content");
    return niri_language_new(conf_to_particle(content, inherited));
}

static bool
verify_conf(keychain_t *chain, const struct yml_node *node)
{
    static struct attr_info const attrs[] = {
        MODULE_COMMON_ATTRS,
    };
    return conf_verify_dict(chain, node, attrs);
}

const struct module_iface module_niri_language_iface = {
    .verify_conf = &verify_conf,
    .from_conf = &from_conf,
};

#if defined(CORE_PLUGINS_AS_SHARED_LIBRARIES)
extern const struct module_iface iface __attribute__((weak, alias("module_niri_language_iface")));
#endif
