#include "plugin.h"

#include <string.h>
#include <dlfcn.h>

#include <tllist.h>

#define LOG_MODULE "plugin"
#define LOG_ENABLE_DBG 0
#include "log.h"
#include "config.h"

#if !defined(CORE_PLUGINS_AS_SHARED_LIBRARIES)

#define EXTERN_MODULE(plug_name)                                        \
    extern const struct module_iface module_##plug_name##_iface;        \
    extern bool plug_name##_verify_conf(                                \
        keychain_t *chain, const struct yml_node *node);                \
    extern struct module *plug_name##_from_conf(                        \
        const struct yml_node *node, struct conf_inherit inherited);

#define EXTERN_PARTICLE(plug_name)                                      \
    extern const struct particle_iface particle_##plug_name##_iface;    \
    extern bool plug_name##_verify_conf(                                \
        keychain_t *chain, const struct yml_node *node);                \
    extern struct particle *plug_name##_from_conf(                      \
        const struct yml_node *node, struct particle *common);

#define EXTERN_DECORATION(plug_name)                                    \
    extern const struct deco_iface deco_##plug_name##_iface;            \
    extern bool plug_name##_verify_conf(                                \
        keychain_t *chain, const struct yml_node *node);                \
    extern struct deco *plug_name##_from_conf(const struct yml_node *node);

#if defined(HAVE_PLUGIN_alsa)
 EXTERN_MODULE(alsa);
#endif
#if defined(HAVE_PLUGIN_backlight)
 EXTERN_MODULE(backlight);
#endif
#if defined(HAVE_PLUGIN_battery)
 EXTERN_MODULE(battery);
#endif
#if defined(HAVE_PLUGIN_clock)
 EXTERN_MODULE(clock);
#endif
#if defined(HAVE_PLUGIN_cpu)
 EXTERN_MODULE(cpu);
#endif
#if defined(HAVE_PLUGIN_disk_io)
 EXTERN_MODULE(disk_io);
#endif
#if defined(HAVE_PLUGIN_dwl)
 EXTERN_MODULE(dwl);
#endif
#if defined(HAVE_PLUGIN_foreign_toplevel)
 EXTERN_MODULE(foreign_toplevel);
#endif
#if defined(HAVE_PLUGIN_mem)
 EXTERN_MODULE(mem);
#endif
#if defined(HAVE_PLUGIN_mpd)
  EXTERN_MODULE(mpd);
#endif
#if defined(HAVE_PLUGIN_i3)
 EXTERN_MODULE(i3);
#endif
#if defined(HAVE_PLUGIN_label)
 EXTERN_MODULE(label);
#endif
#if defined(HAVE_PLUGIN_network)
 EXTERN_MODULE(network);
#endif
#if defined(HAVE_PLUGIN_pipewire)
 EXTERN_MODULE(pipewire);
#endif
#if defined(HAVE_PLUGIN_pulse)
 EXTERN_MODULE(pulse);
#endif
#if defined(HAVE_PLUGIN_removables)
 EXTERN_MODULE(removables);
#endif
#if defined(HAVE_PLUGIN_river)
 EXTERN_MODULE(river);
#endif
#if defined(HAVE_PLUGIN_script)
 EXTERN_MODULE(script);
#endif
#if defined(HAVE_PLUGIN_sway_xkb)
 EXTERN_MODULE(sway_xkb);
#endif
#if defined(HAVE_PLUGIN_xkb)
 EXTERN_MODULE(xkb);
#endif
#if defined(HAVE_PLUGIN_xwindow)
 EXTERN_MODULE(xwindow);
#endif

EXTERN_PARTICLE(empty);
EXTERN_PARTICLE(list);
EXTERN_PARTICLE(map);
EXTERN_PARTICLE(progress_bar);
EXTERN_PARTICLE(ramp);
EXTERN_PARTICLE(string);

EXTERN_DECORATION(background);
EXTERN_DECORATION(border);
EXTERN_DECORATION(stack);
EXTERN_DECORATION(underline);
EXTERN_DECORATION(overline);

#undef EXTERN_DECORATION
#undef EXTERN_PARTICLE
#undef EXTERN_MODULE

#endif

static tll(struct plugin) plugins = tll_init();

static const char *
type2str(enum plugin_type type)
{
    switch (type) {
    case PLUGIN_MODULE:     return "module";
    case PLUGIN_PARTICLE:   return "particle";
    case PLUGIN_DECORATION: return "decoration";
    }

    assert(false && "invalid type");
    return "";
}

static void __attribute__((constructor))
init(void)
{
#if !defined(CORE_PLUGINS_AS_SHARED_LIBRARIES)

#define REGISTER_CORE_PLUGIN(plug_name, func_prefix, plug_type)   \
    do {                                                          \
        tll_push_back(                                            \
            plugins,                                              \
            ((struct plugin){                                     \
                .name = strdup(#plug_name),                       \
                .type = (plug_type),                              \
                .lib = RTLD_DEFAULT,                              \
            }));                                                  \
    } while (0)

#define REGISTER_CORE_MODULE(plug_name, func_prefix)  do {              \
        REGISTER_CORE_PLUGIN(plug_name, func_prefix, PLUGIN_MODULE);    \
        tll_back(plugins).module = &module_##func_prefix##_iface;       \
    } while (0)
#define REGISTER_CORE_PARTICLE(plug_name, func_prefix) do {             \
        REGISTER_CORE_PLUGIN(plug_name, func_prefix, PLUGIN_PARTICLE);  \
        tll_back(plugins).particle = &particle_##func_prefix##_iface;   \
    } while (0)
#define REGISTER_CORE_DECORATION(plug_name, func_prefix) do {           \
        REGISTER_CORE_PLUGIN(plug_name, func_prefix, PLUGIN_DECORATION); \
        tll_back(plugins).decoration = &deco_##func_prefix##_iface;     \
    } while (0)

#if defined(HAVE_PLUGIN_alsa)
    REGISTER_CORE_MODULE(alsa, alsa);
#endif
#if defined(HAVE_PLUGIN_backlight)
    REGISTER_CORE_MODULE(backlight, backlight);
#endif
#if defined(HAVE_PLUGIN_battery)
    REGISTER_CORE_MODULE(battery, battery);
#endif
#if defined(HAVE_PLUGIN_clock)
    REGISTER_CORE_MODULE(clock, clock);
#endif
#if defined(HAVE_PLUGIN_cpu)
    REGISTER_CORE_MODULE(cpu, cpu);
#endif
#if defined(HAVE_PLUGIN_disk_io)
    REGISTER_CORE_MODULE(disk-io, disk_io);
#endif
#if defined(HAVE_PLUGIN_dwl)
    REGISTER_CORE_MODULE(dwl, dwl);
#endif
#if defined(HAVE_PLUGIN_foreign_toplevel)
    REGISTER_CORE_MODULE(foreign-toplevel, foreign_toplevel);
#endif
#if defined(HAVE_PLUGIN_mem)
    REGISTER_CORE_MODULE(mem, mem);
#endif
#if defined(HAVE_PLUGIN_mpd)
    REGISTER_CORE_MODULE(mpd, mpd);
#endif
#if defined(HAVE_PLUGIN_i3)
    REGISTER_CORE_MODULE(i3, i3);
#endif
#if defined(HAVE_PLUGIN_label)
    REGISTER_CORE_MODULE(label, label);
#endif
#if defined(HAVE_PLUGIN_network)
    REGISTER_CORE_MODULE(network, network);
#endif
#if defined(HAVE_PLUGIN_pipewire)
    REGISTER_CORE_MODULE(pipewire, pipewire);
#endif
#if defined(HAVE_PLUGIN_pulse)
    REGISTER_CORE_MODULE(pulse, pulse);
#endif
#if defined(HAVE_PLUGIN_removables)
    REGISTER_CORE_MODULE(removables, removables);
#endif
#if defined(HAVE_PLUGIN_river)
    REGISTER_CORE_MODULE(river, river);
#endif
#if defined(HAVE_PLUGIN_script)
    REGISTER_CORE_MODULE(script, script);
#endif
#if defined(HAVE_PLUGIN_sway_xkb)
    REGISTER_CORE_MODULE(sway-xkb, sway_xkb);
#endif
#if defined(HAVE_PLUGIN_xkb)
    REGISTER_CORE_MODULE(xkb, xkb);
#endif
#if defined(HAVE_PLUGIN_xwindow)
    REGISTER_CORE_MODULE(xwindow, xwindow);
#endif

    REGISTER_CORE_PARTICLE(empty, empty);
    REGISTER_CORE_PARTICLE(list, list);
    REGISTER_CORE_PARTICLE(map, map);
    REGISTER_CORE_PARTICLE(progress-bar, progress_bar);
    REGISTER_CORE_PARTICLE(ramp, ramp);
    REGISTER_CORE_PARTICLE(string, string);

    REGISTER_CORE_DECORATION(background, background);
    REGISTER_CORE_DECORATION(border, border);
    REGISTER_CORE_DECORATION(stack, stack);
    REGISTER_CORE_DECORATION(underline, underline);
    REGISTER_CORE_DECORATION(overline, overline);

#undef REGISTER_CORE_DECORATION
#undef REGISTER_CORE_PARTICLE
#undef REGISTER_CORE_PLUGIN

#endif /* !CORE_PLUGINS_AS_SHARED_LIBRARIES */
}

static void
free_plugin(struct plugin plug)
{
    dlerror();

    if (plug.lib != NULL)
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
            assert(plug->item.dummy != NULL);
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

    tll_push_back(plugins, ((struct plugin){strdup(name), type, lib, {NULL}}));
    struct plugin *plug = &tll_back(plugins);

    dlerror(); /* Clear previous error */
    plug->dummy = dlsym(lib, "iface");

    const char *dl_error = dlerror();
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
    return plug != NULL ? plug->module : NULL;
}

const struct particle_iface *
plugin_load_particle(const char *name)
{
    const struct plugin *plug = plugin_load(name, PLUGIN_PARTICLE);
    return plug != NULL ? plug->particle : NULL;
}

const struct deco_iface *
plugin_load_deco(const char *name)
{
    const struct plugin *plug = plugin_load(name, PLUGIN_DECORATION);
    return plug != NULL ? plug->decoration : NULL;
}
