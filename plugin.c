#include "plugin.h"

#include <string.h>
#include <dlfcn.h>

#define LOG_MODULE "plugin"
#define LOG_ENABLE_DBG 0
#include "log.h"
#include "config.h"
#include "tllist.h"

static tll(struct plugin) plugins = tll_init();

static const char *
type2str(enum plugin_type type)
{
    switch (type) {
    case PLUGIN_MODULE:     return "module";
    case PLUGIN_PARTICLE:   return "particle";
    case PLUGIN_DECORATION: return "decoration";
    }

    return NULL;
}

static void
free_plugin(struct plugin plug)
{
    dlerror();
    dlclose(plug.lib);

    const char *dl_error = dlerror();
    if (dl_error != NULL)
        LOG_ERR("%s: %s: dlclose(): %s", type2str(plug.type), plug.name, dl_error);

    free(plug.name);
}

static void __attribute__((destructor))
fini(void)
{
    tll_free_and_free(plugins, free_plugin);
}

const struct plugin *
plugin_load(const char *name, enum plugin_type type)
{
    tll_foreach(plugins, plug) {
        if (plug->item.type == type && strcmp(plug->item.name, name) == 0) {
            LOG_DBG("%s: %s already loaded: %p", type2str(type), name, plug->item.lib);
            assert(plug->item.dummy.sym1 != NULL);
            assert(plug->item.dummy.sym2 != NULL);
            return &plug->item;
        }
    }


    char path[128];
    snprintf(path, sizeof(path), "%s_%s.so", type2str(type), name);

    /* Not loaded - do it now */
    void *lib = dlopen(path, RTLD_LOCAL | RTLD_NOW);
    LOG_DBG("%s: %s: dlopened to %p", type2str(type), name, lib);

    if (lib == NULL) {
        LOG_ERR("%s: %s: dlopen: %s", type2str(type), name, dlerror());
        return NULL;
    }

    tll_push_back(plugins, ((struct plugin){strdup(name), type, lib, {{NULL}}}));
    struct plugin *plug = &tll_back(plugins);

    dlerror(); /* Clear previous error */
    const char *dl_error = NULL;

    plug->dummy.sym1 = dlsym(lib, "verify_conf");
    dl_error = dlerror();

    if (dl_error == NULL) {
        plug->dummy.sym2 = dlsym(lib, "from_conf");
        dl_error = dlerror();
    }

    if (dl_error != NULL) {
        LOG_ERR("%s: %s: dlsym: %s", type2str(type), name, dl_error);
        return NULL;
    }

    return plug;
}

const struct module_iface *
plugin_load_module(const char *name)
{
    const struct plugin *plug = plugin_load(name, PLUGIN_MODULE);
    return plug != NULL ? &plug->module : NULL;
}

const struct particle_iface *
plugin_load_particle(const char *name)
{
    const struct plugin *plug = plugin_load(name, PLUGIN_PARTICLE);
    return plug != NULL ? &plug->particle : NULL;
}

const struct deco_iface *
plugin_load_deco(const char *name)
{
    const struct plugin *plug = plugin_load(name, PLUGIN_DECORATION);
    return plug != NULL ? &plug->decoration : NULL;
}