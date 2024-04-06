#pragma once

#include "../color.h"
#include "../font-shaping.h"
#include "../module.h"

struct bar {
    int abort_fd;

    void *private;
    int (*run)(struct bar *bar);
    void (*destroy)(struct bar *bar);

    void (*refresh)(const struct bar *bar);
    void (*set_cursor)(struct bar *bar, const char *cursor);

    const char *(*output_name)(const struct bar *bar);
};

enum bar_location { BAR_TOP, BAR_BOTTOM };
enum bar_layer { BAR_LAYER_OVERLAY, BAR_LAYER_TOP, BAR_LAYER_BOTTOM, BAR_LAYER_BACKGROUND };
enum bar_backend { BAR_BACKEND_AUTO, BAR_BACKEND_XCB, BAR_BACKEND_WAYLAND };

struct bar_config {
    enum bar_backend backend;

    const char *monitor;
    enum bar_layer layer;
    enum bar_location location;
    enum font_shaping font_shaping;
    int height;
    int left_spacing, right_spacing;
    int left_margin, right_margin;
    int trackpad_sensitivity;

    pixman_color_t background;

    struct {
        int left_width, right_width;
        int top_width, bottom_width;
        pixman_color_t color;
        int left_margin, right_margin;
        int top_margin, bottom_margin;
    } border;

    struct {
        struct module **mods;
        size_t count;
    } left;
    struct {
        struct module **mods;
        size_t count;
    } center;
    struct {
        struct module **mods;
        size_t count;
    } right;
};

struct bar *bar_new(const struct bar_config *config);
