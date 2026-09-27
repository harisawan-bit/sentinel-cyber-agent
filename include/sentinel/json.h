/* sentinel/json.h — minimal JSON value, parser, and serializer.
 *
 * Sentinel needs JSON in three places: parsing API responses (OSV, CISA KEV,
 * EPSS, crt.sh), carrying plugin metadata, and emitting findings/SARIF.
 * This is a small DOM rather than a streaming parser because metadata is
 * built incrementally and then serialized.
 */
#ifndef SENTINEL_JSON_H
#define SENTINEL_JSON_H

#include <stddef.h>
#include <stdio.h>

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type_t;

typedef struct json_value json_value_t;

struct json_value {
    json_type_t type;
    /* JSON_BOOL */
    int boolean;
    /* JSON_NUMBER */
    double number;
    /* JSON_STRING (owned, NUL-terminated) */
    char *string;
    /* JSON_ARRAY / JSON_OBJECT */
    json_value_t **items;   /* array elements or object values */
    char **keys;            /* object keys (NULL for arrays) */
    size_t count;
    size_t capacity;
};

/* --- construction --- */
json_value_t *json_null(void);
json_value_t *json_bool(int v);
json_value_t *json_number(double v);
json_value_t *json_string(const char *s);
json_value_t *json_array(void);
json_value_t *json_object(void);
void json_free(json_value_t *v);

/* Free only the node itself, not its children. Use this after moving children
 * out into another container, otherwise json_free frees them a second time. */
void json_free_shallow(json_value_t *v);

/* Take ownership of `s` (must be malloc'd) and append to an array. */
void json_array_push(json_value_t *arr, json_value_t *item);

/* Copy `s` into a new owned key. */
void json_object_set(json_value_t *obj, const char *key, json_value_t *value);
void json_object_set_str(json_value_t *obj, const char *key, const char *value);
void json_object_set_num(json_value_t *obj, const char *key, double value);

/* --- access --- */
json_value_t *json_get(const json_value_t *obj, const char *key);
const char *json_get_str(const json_value_t *obj, const char *key);
double json_get_num(const json_value_t *obj, const char *key, double fallback);
json_value_t *json_at(const json_value_t *arr, size_t index);
size_t json_len(const json_value_t *v);

/* Convenience: object[key] as string, or NULL. */
const char *json_str_at(const json_value_t *arr, size_t index);

/* --- parsing --- */
/* Returns NULL on malformed input. Caller frees with json_free(). */
json_value_t *json_parse(const char *text, size_t len);

/* --- serialization --- */
/* Escape a string per RFC 8259 into buf. Returns bytes written (excluding NUL).
 * Used for log lines and HTML attributes; handles control characters. */
size_t json_escape(const char *in, char *out, size_t outlen);

/* Serialize to a newly malloc'd NUL-terminated string. */
char *json_dump(const json_value_t *v, int indent);

/* Write a JSON string value (with quotes) to an already-open stream. */
void json_dump_to(const json_value_t *v, FILE *f, int indent, int depth);

#endif /* SENTINEL_JSON_H */
