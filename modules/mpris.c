#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

#include <poll.h>
#include <tllist.h>

#include <sys/eventfd.h>

#include "dbus.h"
#include "yml.h"

#define LOG_MODULE "mpris"
#define LOG_ENABLE_DBG 0
#include "../bar/bar.h"
#include "../config-verify.h"
#include "../config.h"
#include "../log.h"
#include "../plugin.h"

#define DEFAULT_QUERY_TIMEOUT 500

#define PATH "/org/mpris/MediaPlayer2"
#define BUS_NAME "org.mpris.MediaPlayer2"
#define SERVICE "org.mpris.MediaPlayer2"
#define INTERFACE_ROOT "org.mpris.MediaPlayer2"
#define INTERFACE_PLAYER INTERFACE_ROOT ".Player"

#define DBUS_PATH "/org/freedesktop/DBus"
#define DBUS_BUS_NAME "org.freedesktop.DBus"
#define DBUS_SERVICE "org.freedesktop.DBus"
#define DBUS_INTERFACE_MONITORING "org.freedesktop.DBus.Monitoring"
#define DBUS_INTERFACE_PROPERTIES "org.freedesktop.DBus.Properties"

enum status {
    STATUS_OFFLINE,
    STATUS_PLAYING,
    STATUS_PAUSED,
    STATUS_STOPPED,
    STATUS_ERROR,
};

typedef tll(char *) string_array;

struct metadata {
    uint64_t length_us;
    char *trackid;
    string_array artists;
    char *album;
    char *title;
};

struct property {
    struct metadata metadata;
    char *playback_status;
    char *loop_status;
    uint64_t position_us;
    double rate;
    double volume;
    bool shuffle;
};

struct client {
    bool has_seeked_support;
    enum status status;
    const char *bus_name;
    const char *bus_unique_name;

    struct property property;

    /* The unix timestamp of the last position change (ie.
     * seeking, pausing) */
    struct timespec seeked_when;
};

struct context {
    sd_bus *monitor_connection;
    sd_bus_message *update_message;

    /* FIXME: There is no nice way to pass the desired identities to
     * the event handler for validation. */
    char **identities_ref;
    size_t identities_count;

    tll(struct client *) clients;
    struct client *current_client;

    bool has_update;
};

struct private
{
    thrd_t refresh_thread_id;
    int refresh_abort_fd;

    size_t identities_count;
    size_t timeout_ms;
    const char **identities;
    struct particle *label;

    struct context context;
};

#if 0
static void
debug_print_argument_type(sd_bus_message *message)
{
    char type;
    const char *content;
    sd_bus_message_peek_type(message, &type, &content);
    LOG_DBG("peek_message_type: %c -> %s", type, content);
}
#endif

#if defined(LOG_ENABLE_DBG)
#define dump_type(message)                                                                                             \
    {                                                                                                                  \
        char type;                                                                                                     \
        const char *content;                                                                                           \
        sd_bus_message_peek_type(message, &type, &content);                                                            \
        LOG_DBG("argument layout: %c -> %s", type, content);                                                           \
    }
#endif

static void
metadata_clear(struct metadata *metadata)
{
    tll_free_and_free(metadata->artists, free);

    if (metadata->album != NULL) {
        free(metadata->album);
        metadata->album = NULL;
    }

    if (metadata->title != NULL) {
        free(metadata->title);
        metadata->title = NULL;
    }

    if (metadata->trackid != NULL) {
        free(metadata->trackid);
        metadata->trackid = NULL;
    }
}

static void
property_clear(struct property *property)
{
    metadata_clear(&property->metadata);
    memset(property, 0, sizeof(*property));
}

static void
client_free(struct client *client)
{
    property_clear(&client->property);

    free((void *)client->bus_name);
    free((void *)client->bus_unique_name);
    free(client);
}

static void
clients_free_by_unique_name(struct context *context, const char *unique_name)
{
    tll_foreach(context->clients, it)
    {
        struct client *client = it->item;
        if (strcmp(client->bus_unique_name, unique_name) == 0) {
            LOG_DBG("client_remove: Removing client %s", client->bus_name);
            client_free(client);
            tll_remove(context->clients, it);
        }
    }
}

static void
client_free_all(struct context *context)
{
    tll_free_and_free(context->clients, client_free);
}

static void
client_add(struct context *context, const char *name, const char *unique_name)
{
    struct client *client = malloc(sizeof(*client));
    (*client) = (struct client){
        .bus_name = strdup(name),
        .bus_unique_name = strdup(unique_name),
    };

    tll_push_back(context->clients, client);
    LOG_DBG("client_add: name='%s' unique_name='%s'", name, unique_name);
}

static struct client *
client_lookup_by_unique_name(struct context *context, const char *unique_name)
{
    tll_foreach(context->clients, it)
    {
        struct client *client = it->item;
        if (strcmp(client->bus_unique_name, unique_name) == 0) {
            LOG_DBG("client_lookup: name: %s", client->bus_name);
            return client;
        }
    }

    return NULL;
}

static void
client_change_unique_name(struct client *client, const char *new_name)
{
    if (client->bus_unique_name != NULL) {
        free((void *)client->bus_unique_name);
    }

    client->bus_unique_name = strdup(new_name);
}

static bool
verify_bus_name(char **idents, const size_t ident_count, const char *name)
{
    for (size_t i = 0; i < ident_count; i++) {
        const char *ident = idents[i];

        if (strlen(name) < strlen(BUS_NAME ".") + strlen(ident)) {
            continue;
        }

        const char *cmp = name + strlen(BUS_NAME ".");
        if (strncmp(cmp, ident, strlen(ident)) != 0) {
            continue;
        }

        return true;
    }

    return false;
}

static bool
read_string_array(sd_bus_message *message, string_array *list)
{
    int status = 0;

    /* message argument layout: 'vas' */
    /* enter variant */
    status = sd_bus_message_enter_container(message, SD_BUS_TYPE_VARIANT, "as");
    if (status <= 0) {
        LOG_DBG("unexpected layout: errno=%d (%s)", status, strerror(-status));
        return false;
    }

    /* enter array */
    status = sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "s");
    assert(status >= 0);

    const char *string;
    while ((status = sd_bus_message_read_basic(message, SD_BUS_TYPE_STRING, &string)) > 0) {
        if (strlen(string) > 0) {
            tll_push_back(*list, strdup(string));
        }
    }

    if (status < 0) {
        LOG_ERR("metadata: unexpected layout: errno=%d (%s)", status, strerror(-status));
        return false;
    }

    /* close array */
    sd_bus_message_exit_container(message);
    /* close variant */
    sd_bus_message_exit_container(message);

    return true;
}

static bool
metadata_parse_property(const char *property_name, sd_bus_message *message, struct metadata *buffer)
{
    int status = 0;
    const char *string = NULL;

    char argument_type = 0;
    const char *argument_layout = NULL;
    sd_bus_message_peek_type(message, &argument_type, &argument_layout);
    assert(argument_type == SD_BUS_TYPE_VARIANT);
    assert(argument_layout != NULL && strlen(argument_layout) > 0);

    if (strcmp(property_name, "mpris:trackid") == 0) {
        if (argument_layout[0] != SD_BUS_TYPE_STRING && argument_layout[0] != SD_BUS_TYPE_OBJECT_PATH)
            goto unexpected_type;

        status = sd_bus_message_read(message, "v", argument_layout, &string);
        if (status > 0 && strlen(string) > 0)
            buffer->trackid = strdup(string);

        /* FIXME: "strcmp matches both 'album' as well as 'albumArtist'" */
    } else if (strcmp(property_name, "xesam:album") == 0) {
        status = sd_bus_message_read(message, "v", argument_layout, &string);
        if (status > 0 && strlen(string) > 0)
            buffer->album = strdup(string);

    } else if (strcmp(property_name, "xesam:artist") == 0) {
        status = read_string_array(message, &buffer->artists);

    } else if (strcmp(property_name, "xesam:title") == 0) {
        status = sd_bus_message_read(message, "v", "s", &string);
        if(status > 0 && strlen(string) > 0)
            buffer->title = strdup(string);

    } else if (strcmp(property_name, "mpris:length") == 0) {
        /* MPRIS requires 'mpris:length' to be an i64 (the wording is a bit ambiguous), however some client
         * use a u64 instead. */
        if (argument_layout[0] != SD_BUS_TYPE_INT64 && argument_layout[0] != SD_BUS_TYPE_UINT64)
            goto unexpected_type;

        status = sd_bus_message_read(message, "v", argument_layout, &buffer->length_us);

    } else {
        LOG_DBG("metadata: ignoring property: %s", property_name);
        sd_bus_message_skip(message, NULL);
        return true;
    }

    if (status < 0) {
        LOG_ERR("metadata: failed to read property: arg_type='%c' arg_layout='%s' errno=%d (%s)", argument_type,
                argument_layout, status, strerror(-status));
        return false;
    }

    return true;
unexpected_type:
    LOG_ERR("metadata: unexpected type for '%s'", property_name);
    return false;
}

static bool
metadata_parse_array(struct metadata *metadata, sd_bus_message *message)
{
    int status = sd_bus_message_enter_container(message, SD_BUS_TYPE_VARIANT, "a{sv}");
    if (status <= 0) {
        LOG_DBG("unexpected layout: errno=%d (%s)", status, strerror(-status));
        return false;
    }
    status = sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "{sv}");
    assert(status >= 0);

    while ((status = sd_bus_message_enter_container(message, SD_BUS_TYPE_DICT_ENTRY, "sv")) > 0) {
        const char *property_name = NULL;
        status = sd_bus_message_read_basic(message, SD_BUS_TYPE_STRING, &property_name);
        if (status <= 0) {
            LOG_DBG("unexpected layout: errno=%d (%s)", status, strerror(-status));
            return false;
        }

        status = metadata_parse_property(property_name, message, metadata);
        if (status == 0) {
            return false;
        }

        status = sd_bus_message_exit_container(message);
        assert(status >= 0);
    }

    /* close array */
    sd_bus_message_exit_container(message);
    /* close variant */
    sd_bus_message_exit_container(message);

    return status >= 0;
}

static bool
property_parse(struct property *prop, const char *property_name, sd_bus_message *message)
{
    /* This function is called in two different ways:
     * 1. update_status(): The property is passed directly
     * 2. update_status_from_message(): The property is passed wrapped
     *    inside a variant and has to be unpacked */
    const char *argument_layout = NULL;
    char argument_type = 0;
    int status = sd_bus_message_peek_type(message, &argument_type, &argument_layout);

    assert(status > 0);
    assert(argument_type == SD_BUS_TYPE_VARIANT);
    assert(argument_layout != NULL && strlen(argument_layout) > 0);

    const char *string;
    if (strcmp(property_name, "PlaybackStatus") == 0) {
        status = sd_bus_message_read(message, "v", "s", &string);
        if (status && strlen(string) > 0)
            prop->playback_status = strdup(string);

    } else if (strcmp(property_name, "LoopStatus") == 0) {
        status = sd_bus_message_read(message, "v", "s", &string);
        if (status && strlen(string) > 0)
            prop->loop_status = strdup(string);

    } else if (strcmp(property_name, "Position") == 0) {
        /* MPRIS requires 'Position' to be a i64, however some client
         * use a u64 instead. */
        if (argument_layout[0] != SD_BUS_TYPE_INT64 && argument_layout[0] != SD_BUS_TYPE_UINT64) {
            LOG_ERR("property: unexpected type for '%s'", property_name);
            return false;
        }
        status = sd_bus_message_read(message, "v", argument_layout[0], &prop->position_us);

    } else if (strcmp(property_name, "Shuffle") == 0) {
        status = sd_bus_message_read(message, "v", "b", &prop->shuffle);

    } else if (strcmp(property_name, "Metadata") == 0) {
        metadata_clear(&prop->metadata);
        status = metadata_parse_array(&prop->metadata, message);

    } else {
        LOG_DBG("property: ignoring property: %s", property_name);
        sd_bus_message_skip(message, NULL);
        return true;
    }

    return status > 0;
}

/* ------------- */

static void
format_usec_timestamp(unsigned usec, char *s, size_t sz)
{
    uint32_t secs = usec / 1000 / 1000;
    uint32_t hours = secs / (60 * 60);
    uint32_t minutes = secs % (60 * 60) / 60;
    secs %= 60;

    if (hours > 0)
        snprintf(s, sz, "%02u:%02u:%02u", hours, minutes, secs);
    else
        snprintf(s, sz, "%02u:%02u", minutes, secs);
}

static void
destroy(struct module *mod)
{
    struct private *m = mod->private;
    struct context *context = &m->context;

    client_free_all(context);

    sd_bus_close(context->monitor_connection);

    module_default_destroy(mod);
    m->label->destroy(m->label);
    free(m);
}

static void
context_event_handle_name_owner_changed(sd_bus_message *message, struct context *context)
{
    /* NameOwnerChanged (STRING name, STRING old_owner, STRING new_owner) */
    /* This signal indicates that the owner of a name has changed, ie.
     * it was acquired, lost or changed */

    const char *bus_name = NULL, *old_owner = NULL, *new_owner = NULL;
    int status __attribute__((unused))
        = sd_bus_message_read(message, "sss", &bus_name, &old_owner, &new_owner);
    assert(status > 0);

#if 1
    LOG_DBG("event_handler: 'NameOwnerChanged': bus_name: '%s' old_owner: '%s' new_ower: '%s'", bus_name, old_owner,
            new_owner);
#endif

    if (strlen(new_owner) == 0 && strlen(old_owner) > 0) {
        /* Target bus has been lost */
        struct client *client = client_lookup_by_unique_name(context, old_owner);

        if (client == NULL)
            return;

        LOG_DBG("event_handler: 'NameOwnerChanged': Target bus disappeared: %s", client->bus_name);
        clients_free_by_unique_name(context, client->bus_unique_name);

        if (context->current_client == client)
            context->current_client = NULL;

        return;
    } else if (strlen(old_owner) == 0 && strlen(new_owner) > 0) {
        /* New unique name registered. Not used */
        return;
    }

    /* Name changed */
    assert(new_owner != NULL && strlen(new_owner) > 0);
    assert(old_owner != NULL && strlen(old_owner) > 0);

    struct client *client = client_lookup_by_unique_name(context, old_owner);
    LOG_DBG("'NameOwnerChanged': Name changed from '%s' to '%s' for client '%s'", old_owner, new_owner,
            client->bus_name);
    client_change_unique_name(client, new_owner);
}

static void
context_event_handle_name_acquired(sd_bus_message *message, struct context *context)
{
    /* Spy on applications that requested an "MPRIS style" bus name */

    /* NameAcquired (STRING name) */
    /* " This signal is sent to a specific application when it gains ownership of a name. " */
    const char *name = NULL;
    int status __attribute__((unused))
        = sd_bus_message_read_basic(message, SD_BUS_TYPE_STRING, &name);
    assert(status > 0);

    /*LOG_DBG("event_handler: 'NameAcquired': name: '%s'", name);*/

    if (strncmp(name, BUS_NAME, strlen(BUS_NAME)) != 0) {
        return;
    }

    if (verify_bus_name(context->identities_ref, context->identities_count, name)) {
        const char *unique_name = sd_bus_message_get_destination(message);
        LOG_DBG("'NameAcquired': Acquired new client: %s unique: %s", name, unique_name);
        client_add(context, name, unique_name);
    }
}

static int
context_event_handler(sd_bus_message *message, void *userdata, sd_bus_error *ret_error)
{
    struct context *context = userdata;

    const char *member = sd_bus_message_get_member(message);
    const char *sender = sd_bus_message_get_sender(message);
    const char *path_name = sd_bus_message_get_path(message);

#if 0
    const char *destination = sd_bus_message_get_destination(message);
    const char *self = sd_bus_message_get_sender(message);
    LOG_DBG("member: '%s' self: '%s' dest: '%s' sender: '%s'", member, self,
            destination, sender);
#endif

    if (tll_length(context->clients) == 0 && strcmp(member, "NameAcquired") != 0) {
        return 1;
    }

    /* TODO: Allow multiple clients to connect */
    if (strcmp(path_name, DBUS_PATH) == 0 && strcmp(member, "NameAcquired") == 0) {
        context_event_handle_name_acquired(message, context);
    }

    if (strcmp(path_name, DBUS_PATH) == 0 && strcmp(member, "NameOwnerChanged") == 0) {
        context_event_handle_name_owner_changed(message, context);
        return 1;
    }

    /* Copy the 'PropertiesChanged/Seeked' message, so it can be parsed
     * later on */
    if (strcmp(path_name, PATH) == 0 && (strcmp(member, "PropertiesChanged") == 0 || strcmp(member, "Seeked") == 0)) {
        struct client *client = client_lookup_by_unique_name(context, sender);
        if (client == NULL)
            return 1;

        LOG_DBG("event_handler: '%s': name: '%s' unique_name: '%s'", member, client->bus_name, client->bus_unique_name);

        context->has_update = true;
        context->current_client = client;
        context->update_message = sd_bus_message_ref(message);

        assert(context->update_message != NULL);
    }

    return 1;
}

static bool
context_process_events(struct context *context, uint32_t timeout_ms)
{
    int status = -1;

    status = sd_bus_wait(context->monitor_connection, timeout_ms);
    if (status < 0) {
        if (status == -ENOTCONN)
            LOG_DBG("Disconnect signal has been processed");
        else
            LOG_ERR("Failed to query monitor connection: errno=%d", status);

        return false;
    }

    /* 'sd_bus_process' processes one 'action' per call.
     * This includes: connection, authentication, message processing */
    status = sd_bus_process(context->monitor_connection, NULL);

    if (status < 0) {
        if (status == -ENOTCONN)
            LOG_DBG("Disconnect signal has been processed");
        else
            LOG_ERR("Failed to query monitor connection: errno=%d", status);

        return false;
    }

    return true;
}

static bool
context_new(struct private *m, struct context *context)
{
    int status = true;
    sd_bus *connection;
    if ((status = sd_bus_default_user(&connection)) < 0) {
        LOG_ERR("Failed to connect to the desktop bus. errno: %d", status);
        return -1;
    }

    /* Turn this connection into a monitor */
    sd_bus_message *message;
    status = sd_bus_message_new_method_call(connection, &message, DBUS_SERVICE, DBUS_PATH, DBUS_INTERFACE_MONITORING,
                                            "BecomeMonitor");

    const char *matching_rules[] = {
        /* Listen for... */
        /* ... new MPRIS clients */
        "type='signal',interface='org.freedesktop.DBus',member='NameAcquired',path='/org/freedesktop/"
        "DBus',arg0namespace='org.mpris.MediaPlayer2'",
        /* ... name changes */
        "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged',"
        "path='/org/freedesktop/DBus'",
        /* ... property changes */
        "type='signal',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged', "
        "path='/org/mpris/MediaPlayer2'",
        /* ... changes in playback position */
        "type='signal',interface='org.mpris.MediaPlayer2.Player',member='Seeked', "
        "path='/org/mpris/MediaPlayer2'",
    };

    /* TODO: Error handling */
    /* "BecomeMonitor" ('asu'): (Rules: String[], Flags: UINT32) */
    /* https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-become-monitor */
    status = sd_bus_message_open_container(message, SD_BUS_TYPE_ARRAY, "s");
    for (uint32_t i = 0; i < sizeof(matching_rules) / sizeof(matching_rules[0]); i++) {
        status = sd_bus_message_append(message, "s", matching_rules[i]);
    }
    status = sd_bus_message_close_container(message);
    status = sd_bus_message_append_basic(message, SD_BUS_TYPE_UINT32, &(uint32_t){0});

    sd_bus_message *reply = NULL;
    sd_bus_error error = {};
    status = sd_bus_call(NULL, message, m->timeout_ms, &error, &reply);

    if (status < 0 && sd_bus_error_is_set(&error)) {
        LOG_ERR("context_new: got error response: %s: %s (%d)", error.name, error.message,
                sd_bus_error_get_errno(&error));
        return false;
    }

    sd_bus_message_unref(message);
    sd_bus_message_unref(reply);

    (*context) = (struct context){
        .monitor_connection = connection,
        .identities_ref = (char **)m->identities,
        .identities_count = m->identities_count,
        .clients = tll_init(),
    };

    sd_bus_add_filter(connection, NULL, context_event_handler, context);

    return status >= 0;
}

static uint64_t
timespec_diff_us(const struct timespec *a, const struct timespec *b)
{
    uint64_t nsecs_a = a->tv_sec * 1000000000 + a->tv_nsec;
    uint64_t nsecs_b = b->tv_sec * 1000000000 + b->tv_nsec;

    assert(nsecs_a >= nsecs_b);
    uint64_t nsec_diff = nsecs_a - nsecs_b;
    return nsec_diff / 1000;
}

static bool
update_status_from_message(struct module *mod, sd_bus_message *message)
{
    struct private *m = mod->private;
    mtx_lock(&mod->lock);

    struct client *client = m->context.current_client;
    int status = 1;

    /* Player.Seeked (UINT64 position)*/
    if (strcmp(sd_bus_message_get_member(message), "Seeked") == 0) {
        client->has_seeked_support = true;

        status = sd_bus_message_read_basic(message, SD_BUS_TYPE_INT64, &client->property.position_us);
        if (status <= 0)
            return status;

        clock_gettime(CLOCK_MONOTONIC, &client->seeked_when);
        return true;
    }

    /* Properties.PropertiesChanged (STRING interface_name,
     *                               ARRAY of DICT_ENTRY<STRING,VARIANT> changed_properties,
     *                               ARRAY<STRING> invalidated_properties); */
    assert(strcmp(sd_bus_message_get_member(message), "PropertiesChanged") == 0);
    assert(strcmp(sd_bus_message_get_signature(message, 1), "sa{sv}as") == 0);

    /* argument: 'interface_name' layout: 's' */
    const char *interface_name = NULL;
    sd_bus_message_read_basic(message, SD_BUS_TYPE_STRING, &interface_name);

    if (strcmp(interface_name, INTERFACE_PLAYER) != 0) {
        LOG_DBG("Ignoring interface: %s", interface_name);
        mtx_unlock(&mod->lock);
        return true;
    }

    /* argument: 'changed_properties' layout: 'a{sv}' */

    /* Make sure we reset the position on metadata change unless the
     * update contains its own position value */
    bool should_reset_position = true;
    bool has_entries = sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "{sv}");

    while ((has_entries = sd_bus_message_enter_container(message, SD_BUS_TYPE_DICT_ENTRY, "sv")) > 0) {
        const char *property_name = NULL;
        int status __attribute__((unused))
            = sd_bus_message_read_basic(message, SD_BUS_TYPE_STRING, &property_name);
        assert(status > 0);

        if (!property_parse(&client->property, property_name, message)) {
            return false;
        }

        status = sd_bus_message_exit_container(message);
        assert(status >= 0);

        if (strcmp(property_name, "PlaybackStatus") == 0) {
            if (strcmp(client->property.playback_status, "Stopped") == 0) {
                client->status = STATUS_STOPPED;

            } else if (strcmp(client->property.playback_status, "Playing") == 0) {
                clock_gettime(CLOCK_MONOTONIC, &client->seeked_when);
                client->status = STATUS_PLAYING;

            } else if (strcmp(client->property.playback_status, "Paused") == 0) {
                /* Update our position to include the elapsed time */
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                client->status = STATUS_PAUSED;
                client->property.position_us += timespec_diff_us(&now, &client->seeked_when);
            }
        }

        /* Make sure to reset the position upon metadata/song changes */
        if (should_reset_position && strcmp(property_name, "Metadata") == 0) {
            client->property.position_us = 0;

            if (client->property.playback_status == NULL) {
                client->property.playback_status = "Paused";
                client->status = STATUS_PAUSED;
            }
        }

        if (strcmp(property_name, "Position") == 0) {
            should_reset_position = false;
        }
    }

    status = sd_bus_message_exit_container(message);
    assert(status > 0);

    mtx_unlock(&mod->lock);
    return true;
}

static struct exposable *
content_empty(struct module *mod)
{
    struct private *m = mod->private;

    struct tag_set tags = {
        .tags = (struct tag *[]){
            tag_new_bool(mod, "has-seeked-support", "false"),
            tag_new_string(mod, "state", "offline"),
            tag_new_bool(mod, "shuffle", "false"),
            tag_new_string(mod, "loop", "None"),
            tag_new_int_range(mod, "volume", 0, 0, 100),
            tag_new_string(mod, "album", ""),
            tag_new_string(mod, "artist", ""),
            tag_new_string(mod, "title", ""),
            tag_new_string(mod, "pos", ""),
            tag_new_string(mod, "end", ""),
            tag_new_int_realtime(
                mod, "elapsed", 0, 0, 0, TAG_REALTIME_NONE),
        },
        .count = 10,
    };

    mtx_unlock(&mod->lock);

    struct exposable *exposable = m->label->instantiate(m->label, &tags);

    tag_set_destroy(&tags);
    return exposable;
}

static struct exposable *
content(struct module *mod)
{
    const struct private *m = mod->private;
    const struct client *client = m->context.current_client;

    if (client == NULL) {
        return content_empty(mod);
    }

    const struct metadata *metadata = &client->property.metadata;
    const struct property *property = &client->property;

    /* Calculate the current playback position */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    uint64_t elapsed_us = client->property.position_us;
    uint64_t length_us = metadata->length_us;

    if (client->has_seeked_support && client->status == STATUS_PLAYING) {
        elapsed_us += timespec_diff_us(&now, &client->seeked_when);
        if (elapsed_us > length_us) {
            LOG_DBG("dynamic update of elapsed overflowed: "
                    "elapsed=%" PRIu64 ", duration=%" PRIu64,
                    elapsed_us, length_us);
            elapsed_us = length_us;
        }
    }

    /* Some clients can report misleading or incomplete updates to the
     * playback position, potentially causing the position to exceed
     * the length */
    if (elapsed_us > length_us)
        elapsed_us = length_us = 0;

    char tag_pos_value[16] = {0}, tag_end_value[16] = {0};
    if (length_us > 0) {
        format_usec_timestamp(elapsed_us, tag_pos_value, sizeof(tag_pos_value));
        format_usec_timestamp(length_us, tag_end_value, sizeof(tag_end_value));
    }

    char *tag_state_value = NULL;
    switch (client->status) {
    case STATUS_ERROR:
        tag_state_value = "error";
        break;
    case STATUS_OFFLINE:
        tag_state_value = "offline";
        break;
    case STATUS_PLAYING:
        tag_state_value = "playing";
        break;
    case STATUS_PAUSED:
        tag_state_value = "paused";
        break;
    case STATUS_STOPPED:
        tag_state_value = "stopped";
        break;
    }

    const char *tag_loop_value = (property->loop_status == NULL) ? "" : property->loop_status;
    const char *tag_album_value = (metadata->album == NULL) ? "" : metadata->album;
    const char *tag_artists_value = (tll_length(metadata->artists) <= 0) ? "" : tll_front(metadata->artists);
    const char *tag_title_value = (metadata->title == NULL) ? "" : metadata->title;
    const uint32_t tag_volume_value = (property->volume >= 0.995) ? 100 : 100 * property->volume;
    const bool tag_shuffle_value = property->shuffle;
    const enum tag_realtime_unit realtime_unit
        = (client->has_seeked_support && client->status == STATUS_PLAYING) ? TAG_REALTIME_MSECS : TAG_REALTIME_NONE;

    struct tag_set tags = {
        .tags = (struct tag *[]){
            tag_new_bool(mod, "has_seeked_support", client->has_seeked_support),
            tag_new_bool(mod, "shuffle", tag_shuffle_value),
            tag_new_int_range(mod, "volume", tag_volume_value, 0, 100),
            tag_new_string(mod, "album", tag_album_value),
            tag_new_string(mod, "artist", tag_artists_value),
            tag_new_string(mod, "end", tag_end_value),
            tag_new_string(mod, "loop", tag_loop_value),
            tag_new_string(mod, "pos", tag_pos_value),
            tag_new_string(mod, "state", tag_state_value),
            tag_new_string(mod, "title", tag_title_value),
            tag_new_int_realtime(
                mod, "elapsed", elapsed_us, 0, length_us, realtime_unit),
        },
        .count = 11,
    };

    mtx_unlock(&mod->lock);

    struct exposable *exposable = m->label->instantiate(m->label, &tags);

    tag_set_destroy(&tags);
    return exposable;
}

struct refresh_context {
    struct module *mod;
    int abort_fd;
    long milli_seconds;
};

static int
refresh_in_thread(void *arg)
{
    struct refresh_context *ctx = arg;
    struct module *mod = ctx->mod;

    /* Extract data from context so that we can free it */
    int abort_fd = ctx->abort_fd;
    long milli_seconds = ctx->milli_seconds;
    free(ctx);

    /*LOG_DBG("going to sleep for %ldms", milli_seconds);*/

    /* Wait for timeout, or abort signal */
    struct pollfd fds[] = {{.fd = abort_fd, .events = POLLIN}};
    int r = poll(fds, 1, milli_seconds);

    if (r < 0) {
        LOG_ERRNO("failed to poll() in refresh thread");
        return 1;
    }

    /* Aborted? */
    if (r == 1) {
        assert(fds[0].revents & POLLIN);
        /*LOG_DBG("refresh thread aborted");*/
        return 0;
    }

    LOG_DBG("timed refresh");
    mod->bar->refresh(mod->bar);

    return 0;
}

static bool
refresh_in(struct module *mod, long milli_seconds)
{
    struct private *m = mod->private;

    /* Abort currently running refresh thread */
    if (m->refresh_thread_id != 0) {
        /*LOG_DBG("aborting current refresh thread");*/

        /* Signal abort to thread */
        assert(m->refresh_abort_fd != -1);
        if (write(m->refresh_abort_fd, &(uint64_t){1}, sizeof(uint64_t)) != sizeof(uint64_t)) {
            LOG_ERRNO("failed to signal abort to refresher thread");
            return false;
        }

        /* Wait for it to finish */
        int res;
        thrd_join(m->refresh_thread_id, &res);

        /* Close and cleanup */
        close(m->refresh_abort_fd);
        m->refresh_abort_fd = -1;
        m->refresh_thread_id = 0;
    }

    /* Create a new eventfd, to be able to signal abort to the thread */
    int abort_fd = eventfd(0, EFD_CLOEXEC);
    if (abort_fd == -1) {
        LOG_ERRNO("failed to create eventfd");
        return false;
    }

    /* Thread context */
    struct refresh_context *ctx = malloc(sizeof(*ctx));
    ctx->mod = mod;
    ctx->abort_fd = m->refresh_abort_fd = abort_fd;
    ctx->milli_seconds = milli_seconds;

    /* Create thread */
    int r = thrd_create(&m->refresh_thread_id, &refresh_in_thread, ctx);

    if (r != thrd_success) {
        LOG_ERR("failed to create refresh thread");
        close(m->refresh_abort_fd);
        m->refresh_abort_fd = -1;
        m->refresh_thread_id = 0;
        free(ctx);
    }

    /* Detach - we don't want to have to thrd_join() it */
    // thrd_detach(tid);
    return r == 0;
}

static int
run(struct module *mod)
{
    const struct bar *bar = mod->bar;
    struct private *m = mod->private;

    if (!context_new(m, &m->context)) {
        LOG_ERR("Failed to setup context");
        return -1;
    }

    struct context *context = &m->context;

    int ret = 0;
    bool aborted = false;
    while (ret == 0 && !aborted) {
        const uint32_t timeout_ms = 50;
        struct pollfd fds[] = {{.fd = mod->abort_fd, .events = POLLIN}};

        /* Check for abort event */
        if (poll(fds, 1, timeout_ms) < 0) {
            if (errno == EINTR)
                continue;

            LOG_ERRNO("failed to poll");
            break;
        }

        if (fds[0].revents & POLLIN) {
            aborted = true;
            break;
        }

        if (!context_process_events(context, m->timeout_ms)) {
            aborted = true;
            break;
        }

        /* Process dynamic updates, received through the contexts
         * monitor connection. The 'upate_message' attribute is set
         * inside the contexts event callback, if there are any
         * updates to be processed. */
        if (context->has_update) {
            assert(context->current_client != NULL);
            assert(context->update_message != NULL);

            context->has_update = false;
            aborted = !update_status_from_message(mod, context->update_message);
            context->update_message = sd_bus_message_unref(context->update_message);
        }

        bar->refresh(bar);
    }

    LOG_DBG("exiting");

    return ret;
}

static const char *
description(const struct module *mod)
{
    return "mpris";
}

static struct module *
mpris_new(const char **ident, size_t ident_count, size_t timeout, struct particle *label)
{
    struct private *priv = calloc(1, sizeof(*priv));
    priv->label = label;
    priv->timeout_ms = timeout;
    priv->identities = malloc(sizeof(*ident) * ident_count);
    priv->identities_count = ident_count;

    for (size_t i = 0; i < ident_count; i++) {
        priv->identities[i] = strdup(ident[i]);
    }

    struct module *mod = module_common_new();
    mod->private = priv;
    mod->run = &run;
    mod->destroy = &destroy;
    mod->content = &content;
    mod->description = &description;
    mod->refresh_in = &refresh_in;
    return mod;
}

static struct module *
from_conf(const struct yml_node *node, struct conf_inherit inherited)
{
    const struct yml_node *ident_list = yml_get_value(node, "identities");
    const struct yml_node *query_timeout = yml_get_value(node, "query_timeout");
    const struct yml_node *c = yml_get_value(node, "content");

    size_t timeout_ms = DEFAULT_QUERY_TIMEOUT * 1000;
    if(query_timeout != NULL)
        timeout_ms = yml_value_as_int(query_timeout) * 1000;

    const size_t ident_count = yml_list_length(ident_list);
    const char *ident[ident_count];
    size_t i = 0;
    for (struct yml_list_iter iter = yml_list_iter(ident_list); iter.node != NULL; yml_list_next(&iter), i++) {
        ident[i] = yml_value_as_string(iter.node);
    }

    return mpris_new(ident, ident_count, timeout_ms, conf_to_particle(c, inherited));
}

static bool
conf_verify_indentities(keychain_t *chain, const struct yml_node *node)
{
    return conf_verify_list(chain, node, &conf_verify_string);
}

static bool
verify_conf(keychain_t *chain, const struct yml_node *node)
{
    static const struct attr_info attrs[] = {
        {"identities", true, &conf_verify_indentities},
        {"query_timeout", false, &conf_verify_unsigned},
        MODULE_COMMON_ATTRS,
    };

    return conf_verify_dict(chain, node, attrs);
}

const struct module_iface module_mpris_iface = {
    .verify_conf = &verify_conf,
    .from_conf = &from_conf,
};

#if defined(CORE_PLUGINS_AS_SHARED_LIBRARIES)
extern const struct module_iface iface __attribute__((weak, alias("module_mpris_iface")));
#endif
