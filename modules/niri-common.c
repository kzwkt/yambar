#include <errno.h>
#include <json-c/json.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <threads.h>
#include <unistd.h>

#include "../log.h"
#include "niri-common.h"

#define LOG_MODULE "niri:common"
#define LOG_ENABLE_DBG 0

static struct niri_socket instance = {
    .fd = -1,
    .abort_fd = -1,
};

static void
workspace_free(struct niri_workspace *workspace)
{
    free(workspace->name);
    free(workspace);
}

static void
parser(char *response)
{
    enum json_tokener_error error = json_tokener_success;
    struct json_object *json = json_tokener_parse_verbose(response, &error);
    if (error != json_tokener_success) {
        LOG_WARN("failed to parse niri socket's response");
        return;
    }

    enum niri_event events = 0;
    struct json_object_iterator it = json_object_iter_begin(json);
    struct json_object_iterator end = json_object_iter_end(json);
    while (!json_object_iter_equal(&it, &end)) {
        char const *key = json_object_iter_peek_name(&it);

        // "WorkspacesChanged": {
        //   "workspaces": [
        //     {
        //       "id": 3,
        //       "idx": 1,
        //       "name": null,
        //       "output": "DP-4",
        //       "is_active": true,
        //       "is_focused": true,
        //       "active_window_id": 24
        //     },
        //     ...
        //   ]
        // }
        if (strcmp(key, "WorkspacesChanged") == 0) {
            mtx_lock(&instance.mtx);
            tll_foreach(instance.workspaces, it) { tll_remove_and_free(instance.workspaces, it, workspace_free); }
            mtx_unlock(&instance.mtx);

            json_object *obj = json_object_iter_peek_value(&it);
            json_object *workspaces = json_object_object_get(obj, "workspaces");

            size_t length = json_object_array_length(workspaces);
            for (size_t i = 0; i < length; ++i) {
                json_object *ws_obj = json_object_array_get_idx(workspaces, i);

                // only add workspaces on the current yambar's monitor
                struct json_object *output = json_object_object_get(ws_obj, "output");
                if (strcmp(instance.monitor, json_object_get_string(output)) != 0)
                    continue;

                struct niri_workspace *ws = calloc(1, sizeof(*ws));
                ws->idx = json_object_get_int(json_object_object_get(ws_obj, "idx"));
                ws->id = json_object_get_int(json_object_object_get(ws_obj, "id"));
                ws->active = json_object_get_boolean(json_object_object_get(ws_obj, "is_active"));
                ws->focused = json_object_get_boolean(json_object_object_get(ws_obj, "is_focused"));
                ws->empty = json_object_get_int(json_object_object_get(ws_obj, "active_window_id")) == 0;

                char const *name = json_object_get_string(json_object_object_get(ws_obj, "name"));
                if (name)
                    ws->name = strdup(name);

                mtx_lock(&instance.mtx);
                bool inserted = false;
                tll_foreach(instance.workspaces, it)
                {
                    if (it->item->idx > ws->idx) {
                        tll_insert_before(instance.workspaces, it, ws);
                        inserted = true;
                        break;
                    }
                }
                if (!inserted)
                    tll_push_back(instance.workspaces, ws);
                mtx_unlock(&instance.mtx);

                events |= workspaces_changed;
            }
        }

        // "WorkspaceActivated": {
        //   "id": 7,
        //   "focused":true
        // }
        else if (strcmp(key, "WorkspaceActivated") == 0) {
            json_object *obj = json_object_iter_peek_value(&it);
            int id = json_object_get_int(json_object_object_get(obj, "id"));

            mtx_lock(&instance.mtx);
            tll_foreach(instance.workspaces, it)
            {
                bool b = it->item->id == id;
                it->item->focused = b;
                it->item->active = b;
            }
            mtx_unlock(&instance.mtx);

            events |= workspace_activated;
        }

        // "WorkspaceActiveWindowChanged": {
        //   "workspace_id": 3,
        //   "active_window_id": 8
        // }
        else if (strcmp(key, "WorkspaceActiveWindowChanged") == 0) {
            json_object *obj = json_object_iter_peek_value(&it);
            int id = json_object_get_int(json_object_object_get(obj, "id"));
            bool empty = json_object_get_int(json_object_object_get(obj, "active_window_id")) == 0;

            mtx_lock(&instance.mtx);
            tll_foreach(instance.workspaces, it)
            {
                if (it->item->id == id) {
                    it->item->empty = empty;
                    break;
                }
            }
            mtx_unlock(&instance.mtx);

            events |= workspace_active_window_changed;
        }

        //
        // "KeyboardLayoutsChanged": {
        //   "keyboard_layouts": {
        //     "names": [
        //       "English (US)",
        //       "Russian"
        //     ],
        //     "current_idx": 0
        //   }
        // }
        else if (strcmp(key, "KeyboardLayoutsChanged") == 0) {
            tll_foreach(instance.keyboard_layouts, it) { tll_remove_and_free(instance.keyboard_layouts, it, free); }

            json_object *obj = json_object_iter_peek_value(&it);
            json_object *kb_layouts = json_object_object_get(obj, "keyboard_layouts");

            instance.keyboard_layout_index = json_object_get_int(json_object_object_get(kb_layouts, "current_idx"));

            json_object *names = json_object_object_get(kb_layouts, "names");
            size_t names_length = json_object_array_length(names);
            for (size_t i = 0; i < names_length; ++i) {
                char const *name = json_object_get_string(json_object_array_get_idx(names, i));
                tll_push_back(instance.keyboard_layouts, strdup(name));
            }

            events |= keyboard_layouts_changed;
        }

        // "KeyboardLayoutSwitched": {
        //   "idx": 1
        // }
        else if (strcmp(key, "KeyboardLayoutSwitched") == 0) {
            json_object *obj = json_object_iter_peek_value(&it);
            instance.keyboard_layout_index = json_object_get_int(json_object_object_get(obj, "idx"));

            events |= keyboard_layouts_switched;
        }

        json_object_iter_next(&it);
    }

    json_object_put(json);

    mtx_lock(&instance.mtx);
    tll_foreach(instance.subscribers, it)
    {
        if (it->item->events & events)
            if (write(it->item->fd, &(uint64_t){1}, sizeof(uint64_t)) == -1)
                LOG_ERRNO("failed to write");
    }
    mtx_unlock(&instance.mtx);
}

static int
run(void *userdata)
{
    static char msg[] = "\"EventStream\"\n";
    static char expected[] = "{\"Ok\":\"Handled\"}";

    if (write(instance.fd, msg, sizeof(msg) / sizeof(msg[0])) == -1) {
        LOG_ERRNO("failed to sent message to niri socket");
        return thrd_error;
    }

    static char buffer[8192];
    if (read(instance.fd, buffer, sizeof(buffer) / sizeof(buffer[0]) - 1) == -1) {
        LOG_ERRNO("failed to read response of niri socket");
        return thrd_error;
    }

    char *saveptr;
    char *response = strtok_r(buffer, "\n", &saveptr);
    if (response == NULL || strcmp(expected, response) != 0) {
        // unexpected first response, something went wrong
        LOG_ERR("unexpected response of niri socket");
        return thrd_error;
    }

    while ((response = strtok_r(NULL, "\n", &saveptr)) != NULL)
        parser(response);

    while (true) {
        struct pollfd fds[] = {
            (struct pollfd){.fd = instance.abort_fd, .events = POLLIN},
            (struct pollfd){.fd = instance.fd, .events = POLLIN},
        };

        if (poll(fds, sizeof(fds) / sizeof(fds[0]), -1) == -1) {
            if (errno == EINTR)
                continue;

            LOG_ERRNO("failed to poll");
            break;
        }

        if (fds[0].revents & POLLIN)
            break;

        static char buffer[8192];
        ssize_t length = read(fds[1].fd, buffer, sizeof(buffer) / sizeof(buffer[0]));

        if (length == 0)
            break;

        if (length == -1) {
            if (errno == EAGAIN || errno == EINTR)
                continue;

            LOG_ERRNO("unable to read niri socket");
            break;
        }

        buffer[length] = '\0';
        saveptr = NULL;
        response = strtok_r(buffer, "\n", &saveptr);
        do {
            parser(response);
        } while ((response = strtok_r(NULL, "\n", &saveptr)) != NULL);
    }

    return thrd_success;
}

struct niri_socket *
niri_socket_open(char const *monitor)
{
    if (instance.fd >= 0)
        return &instance;

    char const *path = getenv("NIRI_SOCKET");
    if (path == NULL) {
        LOG_ERR("NIRI_SOCKET is empty. Is niri running?");
        return NULL;
    }

    if ((instance.fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1) {
        LOG_ERRNO("failed to create socket");
        goto error;
    }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(instance.fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        LOG_ERRNO("failed to connect to niri socket");
        goto error;
    }

    if ((instance.abort_fd = eventfd(0, EFD_CLOEXEC)) == -1) {
        LOG_ERRNO("failed to create abort_fd");
        goto error;
    }

    if (mtx_init(&instance.mtx, mtx_plain) != thrd_success) {
        LOG_ERR("failed to initialize mutex");
        goto error;
    }

    if (thrd_create(&instance.thrd, run, NULL) != thrd_success) {
        LOG_ERR("failed to create thread");
        mtx_destroy(&instance.mtx);
        goto error;
    }

    instance.monitor = monitor;

    return &instance;

error:
    if (instance.fd >= 0)
        close(instance.fd);
    if (instance.abort_fd >= 0)
        close(instance.abort_fd);
    instance.fd = -1;
    instance.abort_fd = -1;
    instance.monitor = NULL;

    return NULL;
}

static void
socket_close(void)
{
    if (write(instance.abort_fd, &(uint64_t){1}, sizeof(uint64_t)) != sizeof(uint64_t))
        LOG_ERRNO("failed to write to abort_fd");

    thrd_join(instance.thrd, NULL);

    close(instance.abort_fd);
    close(instance.fd);
    instance.abort_fd = -1;
    instance.fd = -1;

    mtx_destroy(&instance.mtx);

    tll_free_and_free(instance.subscribers, free);
    tll_free_and_free(instance.workspaces, workspace_free);
    tll_free_and_free(instance.keyboard_layouts, free);
}

void
niri_socket_close(void)
{
    static once_flag flag = ONCE_FLAG_INIT;
    call_once(&flag, socket_close);
}

int
niri_socket_subscribe(enum niri_event events)
{
    int fd = eventfd(0, EFD_CLOEXEC);
    if (fd == -1) {
        LOG_ERRNO("failed to create eventfd");
        return -1;
    }

    struct niri_subscriber *subscriber = calloc(1, sizeof(*subscriber));
    subscriber->events = events;
    subscriber->fd = fd;

    mtx_lock(&instance.mtx);
    tll_push_back(instance.subscribers, subscriber);
    mtx_unlock(&instance.mtx);

    return subscriber->fd;
}
