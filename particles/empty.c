#include <stdlib.h>

#include "../config-verify.h"
#include "../config.h"
#include "../particle.h"
#include "../plugin.h"

static int
begin_expose(struct exposable *exposable)
{
    exposable->width = exposable->particle->left_margin + exposable->particle->right_margin;
    return exposable->width;
}

static void
expose(const struct exposable *exposable, pixman_image_t *pix, int x, int y, int height)
{
    exposable_render_deco(exposable, pix, x, y, height);
}

static struct exposable *
instantiate(const struct particle *particle, const struct tag_set *tags)
{
    struct exposable *exposable = exposable_common_new(particle, tags);
    exposable->begin_expose = &begin_expose;
    exposable->expose = &expose;
    return exposable;
}

static struct particle *
empty_new(struct particle *common)
{
    common->destroy = &particle_default_destroy;
    common->instantiate = &instantiate;
    return common;
}

static struct particle *
from_conf(const struct yml_node *node, struct particle *common)
{
    return empty_new(common);
}

static bool
verify_conf(keychain_t *chain, const struct yml_node *node)
{
    static const struct attr_info attrs[] = {
        PARTICLE_COMMON_ATTRS,
    };

    return conf_verify_dict(chain, node, attrs);
}

const struct particle_iface particle_empty_iface = {
    .verify_conf = &verify_conf,
    .from_conf = &from_conf,
};

#if defined(CORE_PLUGINS_AS_SHARED_LIBRARIES)
extern const struct particle_iface iface __attribute__((weak, alias("particle_empty_iface")));
#endif
