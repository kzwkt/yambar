#include "plugin.h"

#include <string.h>
#include <dlfcn.h>

#define LOG_MODULE "plugin"
#define LOG_ENABLE_DBG 0
#include "log.h"
#include "config.h"
#include "tllist.h"

enum plugin_type { PLUGIN_MODULE, PLUGIN_PARTICLE };

struct plugin {
    char *name;
    enum plugin_type type;

    void *lib;
    const void *sym;
};

static tll(struct plugin) plugins = tll_init();

static const char *
type2str(enum plugin_type type)
{
    switch (type) {
    case PLUGIN_MODULE:   return "module";
    case PLUGIN_PARTICLE: return "particle";
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

static const void *
_load_plugin(const char *name, enum plugin_type type)
{
    /* Have we already loaded it? */
    tll_foreach(plugins, plug) {
        if (plug->item.type == type && strcmp(plug->item.name, name) == 0) {
            LOG_DBG("%s: %s already loaded: %p", type2str(type), name, plug->item.lib);
            assert(plug->item.sym != NULL);
            return plug->item.sym;
        }
    }

    char path[128];
    snprintf(path, sizeof(path), "lib%s.so", name);

    /* Not loaded - do it now */
    void *lib = dlopen(path, RTLD_LOCAL | RTLD_NOW);
    LOG_DBG("%s: %s: dlopened to %p", type2str(type), name, lib);

    if (lib == NULL) {
        LOG_ERR("%s: %s: dlopen: %s", type2str(type), name, dlerror());
        return NULL;
    }

    tll_push_back(plugins, ((struct plugin){strdup(name), type, lib, NULL}));
    struct plugin *plug = &tll_back(plugins);

    /* TODO: rename to plugin_info or so, in both modules and particles */
    dlerror(); /* Clear previous error */
    plug->sym = dlsym(lib, type == PLUGIN_MODULE ? "module_info" : "particle_info");

    const char *dlsym_error = dlerror();
    if (dlsym_error != NULL) {
        LOG_ERR("%s: %s: dlsym: %s", type2str(type), name, dlsym_error);
        return NULL;
    }

    assert(plug->sym != NULL);
    return plug->sym;
}

const struct module_info *
plugin_load_module(const char *name)
{
    return _load_plugin(name, PLUGIN_MODULE);
}

const struct particle_info *
plugin_load_particle(const char *name)
{
    return _load_plugin(name, PLUGIN_PARTICLE);
}
