#include "yml.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <tllist.h>
#include <yaml.h>

#define UNUSED __attribute__((unused))

enum yml_error {
    YML_ERR_NONE,
    YML_ERR_DUPLICATE_KEY,
    YML_ERR_INVALID_ANCHOR,
    YML_ERR_UNKNOWN,
};

enum node_type {
    ROOT,
    SCALAR,
    DICT,
    LIST,
};

struct yml_node;

struct dict_pair {
    struct yml_node *key;
    struct yml_node *value;
};

struct anchor_map {
    char *anchor;
    const struct yml_node *node;
};

struct yml_node {
    enum node_type type;
    union {
        struct {
            struct yml_node *root;
            struct anchor_map anchors[100]; /* TODO: dynamic resize */
            size_t anchor_count;
        } root;
        struct {
            char *value;
        } scalar;
        struct {
            tll(struct dict_pair) pairs;
            bool next_is_value;
        } dict;
        struct {
            tll(struct yml_node *) values;
        } list;
    };

    size_t line;
    size_t column;

    struct yml_node *parent;
};

static struct yml_node *
clone_node(struct yml_node *parent, const struct yml_node *node)
{
    struct yml_node *clone = calloc(1, sizeof(*clone));
    clone->type = node->type;
    clone->line = node->line;
    clone->column = node->column;
    clone->parent = parent;

    switch (node->type) {
    case SCALAR:
        clone->scalar.value = strdup(node->scalar.value);
        break;

    case DICT:
        tll_foreach(node->dict.pairs, it)
        {
            struct dict_pair p = {
                .key = clone_node(clone, it->item.key),
                .value = clone_node(clone, it->item.value),
            };
            tll_push_back(clone->dict.pairs, p);
        }
        break;

    case LIST:
        tll_foreach(node->list.values, it) tll_push_back(clone->list.values, clone_node(clone, it->item));
        break;

    case ROOT:
        assert(false);
        break;
    }

    return clone;
}

static bool
node_equal(const struct yml_node *a, const struct yml_node *b)
{
    if (a->type != b->type)
        return false;

    if (a->type != SCALAR) {
        /* TODO... */
        return false;
    }

    return strcmp(a->scalar.value, b->scalar.value) == 0;
}

static bool
dict_has_key(const struct yml_node *node, const struct yml_node *key)
{
    assert(node->type == DICT);

    tll_foreach(node->dict.pairs, pair)
    {
        if (node_equal(pair->item.key, key))
            return true;
    }

    return false;
}

static enum yml_error
add_node(struct yml_node *parent, struct yml_node *new_node, yaml_mark_t loc)
{
    new_node->line = loc.line + 1; /* yaml uses 0-based line numbers */
    new_node->column = loc.column;

    switch (parent->type) {
    case ROOT:
        assert(parent->root.root == NULL);
        parent->root.root = new_node;
        new_node->parent = parent;
        break;

    case DICT:
        if (!parent->dict.next_is_value) {
            if (dict_has_key(parent, new_node))
                return YML_ERR_DUPLICATE_KEY;

            tll_push_back(parent->dict.pairs, (struct dict_pair){.key = new_node});
            parent->dict.next_is_value = true;
        } else {
            tll_back(parent->dict.pairs).value = new_node;
            parent->dict.next_is_value = false;
        }
        new_node->parent = parent;
        break;

    case LIST:
        tll_push_back(parent->list.values, new_node);
        new_node->parent = parent;
        break;

    case SCALAR:
        assert(false);
        return YML_ERR_UNKNOWN;
    }

    return YML_ERR_NONE;
}

static void
add_anchor(struct yml_node *root, const char *anchor, const struct yml_node *node)
{
    assert(root->type == ROOT);

    struct anchor_map *map = &root->root.anchors[root->root.anchor_count];
    map->anchor = strdup(anchor);
    map->node = node;
    root->root.anchor_count++;
}

static bool
post_process(struct yml_node *node, char **error)
{
    switch (node->type) {
    case ROOT:
        if (node->root.root != NULL)
            if (!post_process(node->root.root, error))
                return false;
        break;

    case SCALAR:
        // assert(strcmp(node->scalar.value, "<<") != 0);
        break;

    case LIST:
        tll_foreach(node->list.values, it) if (!post_process(it->item, error)) return false;
        break;

    case DICT:
        tll_foreach(node->dict.pairs, it)
        {
            if (!post_process(it->item.key, error) || !post_process(it->item.value, error)) {
                return false;
            }
        }

        tll_foreach(node->dict.pairs, it)
        {
            if (it->item.key->type != SCALAR)
                continue;

            if (strcmp(it->item.key->scalar.value, "<<") != 0)
                continue;

            if (it->item.value->type == LIST) {
                /*
                 * Merge value is a list (of dictionaries)
                 * e.g. <<: [*foo, *bar]
                 */
                tll_foreach(it->item.value->list.values, v_it)
                {
                    if (v_it->item->type != DICT) {
                        int cnt = snprintf(NULL, 0, "%zu:%zu: cannot merge non-dictionary anchor", v_it->item->line,
                                           v_it->item->column);
                        *error = malloc(cnt + 1);
                        snprintf(*error, cnt + 1, "%zu:%zu: cannot merge non-dictionary anchor", v_it->item->line,
                                 v_it->item->column);
                        return false;
                    }

                    tll_foreach(v_it->item->dict.pairs, vv_it)
                    {
                        struct dict_pair p = {
                            .key = vv_it->item.key,
                            .value = vv_it->item.value,
                        };

                        if (dict_has_key(node, vv_it->item.key)) {
                            /* Prefer value in target dictionary, over the
                             * value from the anchor */
                            yml_destroy(vv_it->item.key);
                            yml_destroy(vv_it->item.value);
                        } else {
                            tll_push_back(node->dict.pairs, p);
                        }
                    }

                    /* Destroy list, but don't free (since its nodes
                     * have been moved to this node), *before*
                     * destroying the key/value nodes. This ensures
                     * the dict nodes aren't free:d in the
                     * yml_destroy() below). */
                    tll_free(v_it->item->dict.pairs);
                }
            } else {
                /*
                 * Merge value is a dictionary only
                 * e.g. <<: *foo
                 */
                if (it->item.value->type != DICT) {
                    int cnt = snprintf(NULL, 0, "%zu:%zu: cannot merge non-dictionary anchor", it->item.value->line,
                                       it->item.value->column);
                    *error = malloc(cnt + 1);
                    snprintf(*error, cnt + 1, "%zu:%zu: cannot merge non-dictionary anchor", it->item.value->line,
                             it->item.value->column);
                    return false;
                }

                tll_foreach(it->item.value->dict.pairs, v_it)
                {
                    struct dict_pair p = {
                        .key = v_it->item.key,
                        .value = v_it->item.value,
                    };

                    if (dict_has_key(node, v_it->item.key)) {
                        /* Prefer value in target dictionary, over the
                         * value from the anchor */
                        yml_destroy(v_it->item.key);
                        yml_destroy(v_it->item.value);
                    } else {
                        tll_push_back(node->dict.pairs, p);
                    }
                }

                /* Destroy list here, *without* freeing nodes (since
                 * nodes have been moved to this node), *before*
                 * destroying the key/value nodes. This ensures the
                 * dict nodes aren't free:d in the yml_destroy()
                 * below */
                tll_free(it->item.value->dict.pairs);
            }

            yml_destroy(it->item.key);
            yml_destroy(it->item.value);

            tll_remove(node->dict.pairs, it);
        }
        break;
    }

    return true;
}

static const char *
format_error(enum yml_error err, const struct yml_node *parent, const struct yml_node *node, const char *anchor)
{
    static char err_str[512];

    switch (err) {
    case YML_ERR_NONE:
        assert(false);
        break;

    case YML_ERR_DUPLICATE_KEY: {
        /* Find parent's key (i.e its name) */
        if (parent->parent != NULL && parent->parent->type == DICT && node->type == SCALAR) {
            tll_foreach(parent->parent->dict.pairs, pair)
            {
                if (pair->item.value != parent)
                    continue;

                if (pair->item.key->type != SCALAR)
                    break;

                assert(pair->item.key->type == SCALAR);
                assert(node->type == SCALAR);

                snprintf(err_str, sizeof(err_str), "%s: duplicate key: '%s'", pair->item.key->scalar.value,
                         node->scalar.value);
                return err_str;
            }
        }

        if (node->type == SCALAR) {
            snprintf(err_str, sizeof(err_str), "duplicate key: %s", node->scalar.value);
        } else
            snprintf(err_str, sizeof(err_str), "duplicate key");
        break;
    }

    case YML_ERR_INVALID_ANCHOR:
        if (parent->parent != NULL && parent->parent->type == DICT) {
            tll_foreach(parent->parent->dict.pairs, pair)
            {
                if (pair->item.value != parent)
                    continue;
                if (pair->item.key->type != SCALAR)
                    break;

                snprintf(err_str, sizeof(err_str), "%s: invalid anchor: %s", pair->item.key->scalar.value,
                         anchor != NULL ? anchor : "<unknown>");
                return err_str;
            }
        }

        snprintf(err_str, sizeof(err_str), "invalid anchor: %s", anchor != NULL ? anchor : "<unknown>");
        break;

    case YML_ERR_UNKNOWN:
        snprintf(err_str, sizeof(err_str), "unknown error");
        break;
    }

    return err_str;
}

static char *
replace_env_variables(const char *str, size_t len)
{
    char *result = strndup(str, len);
    char *start, *key;
    const char *end, *env_value;
    const char* prefix = "${";
    const char* suffix = "}";
    const size_t pref_len = 2;
    const size_t suff_len = 1;
    size_t key_len;

    while ((start = strstr(result, prefix)) != NULL &&
           (end = strstr(start, suffix)) != NULL)
    {
        key_len = end - start - pref_len;
        key = strndup(start + pref_len, key_len);
        env_value = getenv(key);

        if (env_value) {
            size_t result_len = strlen(result);
            size_t new_len = result_len - key_len - pref_len - suff_len + strlen(env_value);
            char *new_result = malloc(new_len + 1);

            strncpy(new_result, result, start - result);
            new_result[start - result] = '\0';
            strcat(new_result, env_value);
            strcat(new_result, end + 1);

            free(result);
            result = new_result;
        } else {
            memmove(start, end + 1, strlen(end + 1) + 1);
        }

        free(key);
    }

    return result;
}

struct yml_node *
yml_load(FILE *yml, char **error)
{
    yaml_parser_t yaml;
    yaml_parser_initialize(&yaml);

    yaml_parser_set_input_file(&yaml, yml);

    bool done = false;
    int indent UNUSED = 0;

    struct yml_node *root = malloc(sizeof(*root));
    root->type = ROOT;
    root->root.root = NULL;
    root->root.anchor_count = 0;

    struct yml_node *n = root;

    const char *error_str = NULL;

    while (!done) {
        yaml_event_t event;
        if (!yaml_parser_parse(&yaml, &event)) {
            if (error != NULL) {
                int cnt = snprintf(NULL, 0, "%zu:%zu: %s %s", yaml.problem_mark.line + 1, yaml.problem_mark.column,
                                   yaml.problem, yaml.context != NULL ? yaml.context : "");

                *error = malloc(cnt + 1);
                snprintf(*error, cnt + 1, "%zu:%zu: %s %s", yaml.problem_mark.line + 1, yaml.problem_mark.column,
                         yaml.problem, yaml.context != NULL ? yaml.context : "");
            }

            goto err_no_error_formatting;
        }

        switch (event.type) {
        case YAML_NO_EVENT:
            break;

        case YAML_STREAM_START_EVENT:
            indent += 2;
            break;

        case YAML_STREAM_END_EVENT:
            indent -= 2;
            done = true;
            break;

        case YAML_DOCUMENT_START_EVENT:
            indent += 2;
            break;

        case YAML_DOCUMENT_END_EVENT:
            indent -= 2;
            break;

        case YAML_ALIAS_EVENT: {
            bool got_match = false;
            for (size_t i = 0; i < root->root.anchor_count; i++) {
                const struct anchor_map *map = &root->root.anchors[i];

                if (strcmp(map->anchor, (const char *)event.data.alias.anchor) != 0)
                    continue;

                struct yml_node *clone = clone_node(NULL, map->node);
                assert(clone != NULL);

                enum yml_error err = add_node(n, clone, event.start_mark);
                if (err != YML_ERR_NONE) {
                    error_str = format_error(err, n, clone, NULL);
                    yml_destroy(clone);
                    yaml_event_delete(&event);
                    goto err;
                }

                got_match = true;
                break;
            }

            if (!got_match) {
                error_str = format_error(YML_ERR_INVALID_ANCHOR, n, NULL, (const char *)event.data.alias.anchor);
                yaml_event_delete(&event);
                goto err;
            }
            break;
        }

        case YAML_SCALAR_EVENT: {
            struct yml_node *new_scalar = calloc(1, sizeof(*new_scalar));
            new_scalar->type = SCALAR;
            new_scalar->scalar.value = replace_env_variables((const char *)event.data.scalar.value, event.data.scalar.length);

            enum yml_error err = add_node(n, new_scalar, event.start_mark);
            if (err != YML_ERR_NONE) {
                error_str = format_error(err, n, new_scalar, NULL);
                yml_destroy(new_scalar);
                yaml_event_delete(&event);
                goto err;
            }

            if (event.data.scalar.anchor != NULL) {
                const char *anchor = (const char *)event.data.scalar.anchor;
                add_anchor(root, anchor, new_scalar);
            }

            break;
        }

        case YAML_SEQUENCE_START_EVENT: {
            indent += 2;
            struct yml_node *new_list = calloc(1, sizeof(*new_list));
            new_list->type = LIST;

            enum yml_error err = add_node(n, new_list, event.start_mark);
            if (err != YML_ERR_NONE) {
                error_str = format_error(err, n, new_list, NULL);
                yml_destroy(new_list);
                yaml_event_delete(&event);
                goto err;
            }

            n = new_list;

            if (event.data.sequence_start.anchor != NULL) {
                const char *anchor = (const char *)event.data.sequence_start.anchor;
                add_anchor(root, anchor, new_list);
            }
            break;
        }

        case YAML_SEQUENCE_END_EVENT:
            indent -= 2;
            assert(n->parent != NULL);
            n = n->parent;
            break;

        case YAML_MAPPING_START_EVENT: {
            indent += 2;

            struct yml_node *new_dict = calloc(1, sizeof(*new_dict));
            new_dict->type = DICT;

            enum yml_error err = add_node(n, new_dict, event.start_mark);
            if (err != YML_ERR_NONE) {
                error_str = format_error(err, n, new_dict, NULL);
                yml_destroy(new_dict);
                yaml_event_delete(&event);
                goto err;
            }

            n = new_dict;

            if (event.data.mapping_start.anchor != NULL) {
                const char *anchor = (const char *)event.data.mapping_start.anchor;
                add_anchor(root, anchor, new_dict);
            }
            break;
        }

        case YAML_MAPPING_END_EVENT:
            assert(!n->dict.next_is_value);
            indent -= 2;
            assert(n->parent != NULL);
            n = n->parent;
            break;
        }

        yaml_event_delete(&event);
    }

    yaml_parser_delete(&yaml);

    if (!post_process(root, error)) {
        yml_destroy(root);
        return NULL;
    }
    return root;

err:
    if (error_str != NULL) {
        int cnt = snprintf(NULL, 0, "%zu:%zu: %s", yaml.mark.line + 1, yaml.mark.column, error_str);
        *error = malloc(cnt + 1);
        snprintf(*error, cnt + 1, "%zu:%zu: %s", yaml.mark.line + 1, yaml.mark.column, error_str);
    } else {
        int cnt = snprintf(NULL, 0, "%zu:%zu: unknown error", yaml.mark.line + 1, yaml.mark.column);
        *error = malloc(cnt + 1);
        snprintf(*error, cnt + 1, "%zu:%zu: unknown error", yaml.mark.line + 1, yaml.mark.column);
    }

err_no_error_formatting:

    yml_destroy(root);
    yaml_parser_delete(&yaml);
    return NULL;
}

void
yml_destroy(struct yml_node *node)
{
    if (node == NULL)
        return;

    switch (node->type) {
    case ROOT:
        yml_destroy(node->root.root);
        for (size_t i = 0; i < node->root.anchor_count; i++)
            free(node->root.anchors[i].anchor);
        break;

    case SCALAR:
        free(node->scalar.value);
        break;

    case LIST:
        tll_free_and_free(node->list.values, yml_destroy);
        break;

    case DICT:
        tll_foreach(node->dict.pairs, it)
        {
            yml_destroy(it->item.key);
            yml_destroy(it->item.value);
        }
        tll_free(node->dict.pairs);
        break;
    }

    free(node);
}

bool
yml_is_scalar(const struct yml_node *node)
{
    return node->type == SCALAR;
}

bool
yml_is_dict(const struct yml_node *node)
{
    return node->type == DICT;
}

bool
yml_is_list(const struct yml_node *node)
{
    return node->type == LIST;
}

static struct yml_node const *
yml_get_(struct yml_node const *node, char const *_path, bool value)
{
    /* value: true for value, false for key */

    if (node != NULL && node->type == ROOT)
        node = node->root.root;

    if (node == NULL)
        return NULL;

    char *path = strdup(_path);

    for (const char *part = strtok(path, "."), *next_part = strtok(NULL, "."); part != NULL;
         part = next_part, next_part = strtok(NULL, ".")) {
        assert(yml_is_dict(node));

        tll_foreach(node->dict.pairs, it)
        {
            assert(yml_is_scalar(it->item.key));
            if (strcmp(it->item.key->scalar.value, part) == 0) {
                if (next_part == NULL) {
                    free(path);

                    if (value)
                        return it->item.value;
                    else
                        return it->item.key;
                }

                node = it->item.value;
                break;
            }
        }
    }

    free(path);
    return NULL;
}

const struct yml_node *
yml_get_value(const struct yml_node *node, const char *_path)
{
    return yml_get_(node, _path, true);
}

struct yml_node const *
yml_get_key(struct yml_node const *node, char const *_path)
{
    return yml_get_(node, _path, false);
}

struct yml_list_iter
yml_list_iter(const struct yml_node *list)
{
    assert(yml_is_list(list));
    tll_foreach(list->list.values, it)
    {
        return (struct yml_list_iter){
            .node = it->item,
            .private = it,
        };
    }

    return (struct yml_list_iter){
        .node = NULL,
        .private = NULL,
    };
}

void
yml_list_next(struct yml_list_iter *iter)
{
    if (iter->private == NULL)
        return;

    const struct yml_node *d = (const void *)(uintptr_t)0xdeadbeef;
    __typeof__(d->list.values.head) it = (__typeof__(d->list.values.head))iter->private;
    __typeof__(d->list.values.head) next = it->next;

    iter->node = next != NULL ? next->item : NULL;
    iter->private = next;
}

size_t
yml_list_length(const struct yml_node *list)
{
    assert(yml_is_list(list));

    size_t length = 0;
    for (struct yml_list_iter it = yml_list_iter(list); it.node != NULL; yml_list_next(&it), length++)
        ;

    return length;
}

struct yml_dict_iter
yml_dict_iter(const struct yml_node *dict)
{
    assert(yml_is_dict(dict));

    tll_foreach(dict->dict.pairs, it)
    {
        return (struct yml_dict_iter){
            .key = it->item.key,
            .value = it->item.value,
            .private1 = it,
        };
    }

    return (struct yml_dict_iter){
        .key = NULL,
        .value = NULL,
        .private1 = NULL,
    };
}

void
yml_dict_next(struct yml_dict_iter *iter)
{
    const struct yml_node *d = (const void *)(uintptr_t)0xdeadbeef;
    __typeof__(d->dict.pairs.head) it = (__typeof__(d->dict.pairs.head))iter->private1;

    if (it == NULL)
        return;

    __typeof__(d->dict.pairs.head) next = it->next;
    iter->key = next != NULL ? next->item.key : NULL;
    iter->value = next != NULL ? next->item.value : NULL;
    iter->private1 = next;
}

size_t
yml_dict_length(const struct yml_node *dict)
{
    assert(yml_is_dict(dict));
    return tll_length(dict->dict.pairs);
}

const char *
yml_value_as_string(const struct yml_node *value)
{
    if (!yml_is_scalar(value))
        return NULL;
    return value->scalar.value;
}

static bool
_as_int(const struct yml_node *value, long *ret)
{
    const char *s = yml_value_as_string(value);
    if (s == NULL)
        return false;

    int cnt;
    int res = sscanf(s, "%ld%n", ret, &cnt);
    return res == 1 && strlen(s) == (size_t)cnt;
}

bool
yml_value_is_int(const struct yml_node *value)
{
    long dummy;
    return _as_int(value, &dummy);
}

long
yml_value_as_int(const struct yml_node *value)
{
    long ret = -1;
    _as_int(value, &ret);
    return ret;
}

static bool
_as_bool(const struct yml_node *value, bool *ret)
{
    if (!yml_is_scalar(value))
        return false;

    const char *v = yml_value_as_string(value);
    if (strcasecmp(v, "y") == 0 || strcasecmp(v, "yes") == 0 || strcasecmp(v, "true") == 0
        || strcasecmp(v, "on") == 0) {
        *ret = true;
        return true;
    } else if (strcasecmp(v, "n") == 0 || strcasecmp(v, "no") == 0 || strcasecmp(v, "false") == 0
               || strcasecmp(v, "off") == 0) {
        *ret = false;
        return true;
    }

    return false;
}

bool
yml_value_is_bool(const struct yml_node *value)
{
    bool dummy;
    return _as_bool(value, &dummy);
}

bool
yml_value_as_bool(const struct yml_node *value)
{
    bool ret = false;
    _as_bool(value, &ret);
    return ret;
}

size_t
yml_source_line(const struct yml_node *node)
{
    return node->line;
}

size_t
yml_source_column(const struct yml_node *node)
{
    return node->column;
}

static void
_print_node(const struct yml_node *n, int indent)
{
    if (n == NULL)
        return;

    switch (n->type) {
    case ROOT:
        _print_node(n->root.root, indent);
        break;

    case DICT:
        tll_foreach(n->dict.pairs, it)
        {
            _print_node(it->item.key, indent);
            printf(": ");

            if (it->item.value->type != SCALAR) {
                printf("\n");
                _print_node(it->item.value, indent + 2);
            } else {
                _print_node(it->item.value, 0);
                printf("\n");
            }
        }
        break;

    case LIST:
        tll_foreach(n->list.values, it)
        {
            printf("%*s- ", indent, "");
            if (it->item->type != SCALAR) {
                printf("\n");
                _print_node(it->item, indent + 2);
            } else {
                _print_node(it->item, 0);
            }
        }
        break;

    case SCALAR:
        printf("%*s%s", indent, "", n->scalar.value);
        break;
    }
}

void
print_node(const struct yml_node *n)
{
    _print_node(n, 0);
}
