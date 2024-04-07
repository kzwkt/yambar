#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#define LOG_MODULE "ramp"
#define LOG_ENABLE_DBG 0
#include "../config-verify.h"
#include "../config.h"
#include "../log.h"
#include "../particle.h"
#include "../plugin.h"

struct private
{
    char *tag;
    bool use_custom_min;
    long min;
    bool use_custom_max;
    long max;
    struct particle **particles;
    size_t count;
};

struct eprivate {
    struct exposable *exposable;
};

static void
exposable_destroy(struct exposable *exposable)
{
    struct eprivate *e = exposable->private;
    e->exposable->destroy(e->exposable);

    free(e);
    exposable_default_destroy(exposable);
}

static int
begin_expose(struct exposable *exposable)
{
    struct eprivate *e = exposable->private;

    int width = e->exposable->begin_expose(e->exposable);
    assert(width >= 0);

    if (width > 0)
        width += exposable->particle->left_margin + exposable->particle->right_margin;

    exposable->width = width;
    return exposable->width;
}

static void
expose(const struct exposable *exposable, pixman_image_t *pix, int x, int y, int height)
{
    struct eprivate *e = exposable->private;

    exposable_render_deco(exposable, pix, x, y, height);
    e->exposable->expose(e->exposable, pix, x + exposable->particle->left_margin, y, height);
}

static void
on_mouse(struct exposable *exposable, struct bar *bar, enum mouse_event event, enum mouse_button btn, int x, int y)
{
    const struct particle *p = exposable->particle;
    const struct eprivate *e = exposable->private;

    if ((event == ON_MOUSE_MOTION && exposable->particle->have_on_click_template) || exposable->on_click[btn] != NULL) {
        /* We have our own handler */
        exposable_default_on_mouse(exposable, bar, event, btn, x, y);
        return;
    }

    int px = p->left_margin;
    if (x >= px && x < px + e->exposable->width) {
        if (e->exposable->on_mouse != NULL)
            e->exposable->on_mouse(e->exposable, bar, event, btn, x - px, y);
        return;
    }

    /* In the left- or right margin */
    exposable_default_on_mouse(exposable, bar, event, btn, x, y);
}

static void
particle_destroy(struct particle *particle)
{
    struct private *p = particle->private;

    for (size_t i = 0; i < p->count; i++)
        p->particles[i]->destroy(p->particles[i]);

    free(p->tag);
    free(p->particles);
    free(p);
    particle_default_destroy(particle);
}

static struct exposable *
instantiate(const struct particle *particle, const struct tag_set *tags)
{
    const struct private *p = particle->private;
    const struct tag *tag = tag_for_name(tags, p->tag);

    assert(p->count > 0);

    long value = tag != NULL ? tag->as_int(tag) : 0;
    long min = tag != NULL ? tag->min(tag) : 0;
    long max = tag != NULL ? tag->max(tag) : 0;

    min = p->use_custom_min ? p->min : min;
    max = p->use_custom_max ? p->max : max;

    if (min > max) {
        LOG_WARN("tag's minimum value is greater than its maximum: "
                 "tag=\"%s\", min=%ld, max=%ld",
                 p->tag, min, max);
        min = max;
    }

    if (value < min) {
        LOG_WARN("tag's value is less than its minimum value: "
                 "tag=\"%s\", min=%ld, value=%ld",
                 p->tag, min, value);
        value = min;
    }
    if (value > max) {
        LOG_WARN("tag's value is greater than its maximum value: "
                 "tag=\"%s\", max=%ld, value=%ld",
                 p->tag, max, value);
        value = max;
    }

    assert(value >= min && value <= max);
    assert(max >= min);

    size_t idx = 0;
    if (max - min > 0)
        idx = p->count * (value - min) / (max - min);

    if (idx == p->count)
        idx--;
    /*
     * printf("ramp: value: %lu, min: %lu, max: %lu, progress: %f, idx: %zu\n",
     *        value, min, max, progress, idx);
     */
    assert(idx >= 0 && idx < p->count);

    struct particle *pp = p->particles[idx];

    struct eprivate *e = calloc(1, sizeof(*e));
    e->exposable = pp->instantiate(pp, tags);
    assert(e->exposable != NULL);

    struct exposable *exposable = exposable_common_new(particle, tags);
    exposable->private = e;
    exposable->destroy = &exposable_destroy;
    exposable->begin_expose = &begin_expose;
    exposable->expose = &expose;
    exposable->on_mouse = &on_mouse;
    return exposable;
}

static struct particle *
ramp_new(struct particle *common, const char *tag, struct particle *particles[], size_t count, bool use_custom_min,
         long min, bool use_custom_max, long max)
{

    struct private *priv = calloc(1, sizeof(*priv));
    priv->tag = strdup(tag);
    priv->particles = malloc(count * sizeof(priv->particles[0]));
    priv->count = count;
    priv->use_custom_max = use_custom_max;
    priv->max = max;
    priv->use_custom_min = use_custom_min;
    priv->min = min;

    for (size_t i = 0; i < count; i++)
        priv->particles[i] = particles[i];

    common->private = priv;
    common->destroy = &particle_destroy;
    common->instantiate = &instantiate;
    return common;
}

static struct particle *
from_conf(const struct yml_node *node, struct particle *common)
{
    const struct yml_node *tag = yml_get_value(node, "tag");
    const struct yml_node *items = yml_get_value(node, "items");
    const struct yml_node *min = yml_get_value(node, "min");
    const struct yml_node *max = yml_get_value(node, "max");

    size_t count = yml_list_length(items);
    struct particle *parts[count];

    size_t idx = 0;
    for (struct yml_list_iter it = yml_list_iter(items); it.node != NULL; yml_list_next(&it), idx++) {
        parts[idx]
            = conf_to_particle(it.node, (struct conf_inherit){common->font, common->font_shaping, common->foreground});
    }

    long min_v = min != NULL ? yml_value_as_int(min) : 0;
    long max_v = max != NULL ? yml_value_as_int(max) : 0;

    return ramp_new(common, yml_value_as_string(tag), parts, count, min != NULL, min_v, max != NULL, max_v);
}

static bool
verify_conf(keychain_t *chain, const struct yml_node *node)
{
    static const struct attr_info attrs[] = {
        {"tag", true, &conf_verify_string},
        {"items", true, &conf_verify_particle_list_items},
        {"min", false, &conf_verify_int},
        {"max", false, &conf_verify_int},
        PARTICLE_COMMON_ATTRS,
    };

    return conf_verify_dict(chain, node, attrs);
}

const struct particle_iface particle_ramp_iface = {
    .verify_conf = &verify_conf,
    .from_conf = &from_conf,
};

#if defined(CORE_PLUGINS_AS_SHARED_LIBRARIES)
extern const struct particle_iface iface __attribute__((weak, alias("particle_ramp_iface")));
#endif
