#pragma once

#include <stdbool.h>
#include <threads.h>
#include <tllist.h>

enum niri_event {
    workspaces_changed = (1 << 0),
    workspace_activated = (1 << 1),
    workspace_active_window_changed = (1 << 2),
    keyboard_layouts_changed = (1 << 3),
    keyboard_layouts_switched = (1 << 4),
};

struct niri_subscriber {
    int events;
    int fd;
};

struct niri_workspace {
    int id;
    int idx;
    char *name;
    bool active;
    bool focused;
    bool empty;
};

struct niri_socket {
    char const *monitor;
    int abort_fd;
    int fd;

    tll(struct niri_subscriber *) subscribers;
    tll(struct niri_workspace *) workspaces;
    tll(char *) keyboard_layouts;
    size_t keyboard_layout_index;

    thrd_t thrd;
    mtx_t mtx;
};

struct niri_socket *niri_socket_open(char const *monitor);
void niri_socket_close(void);
int niri_socket_subscribe(enum niri_event events);
