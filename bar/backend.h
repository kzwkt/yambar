#pragma once

#include <stdbool.h>

#include "bar.h"

struct backend {
    bool (*setup)(struct bar *bar);
    void (*cleanup)(struct bar *bar);
    void (*loop)(struct bar *bar, void (*expose)(const struct bar *bar),
                 void (*on_mouse)(struct bar *bar, enum mouse_event event, enum mouse_button btn, int x, int y));
    void (*commit)(const struct bar *bar);
    void (*refresh)(const struct bar *bar);
    void (*set_cursor)(struct bar *bar, const char *cursor);
    const char *(*output_name)(const struct bar *bar);
};
