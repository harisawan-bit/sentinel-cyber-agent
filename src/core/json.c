/* json.c — JSON value, recursive-descent parser, serializer, and escaping. */
#include "sentinel/json.h"
#include "sentinel/buf.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static json_value_t *alloc_value(json_type_t t)
{
    json_value_t *v = calloc(1, sizeof(*v));
    if (v) v->type = t;
    return v;
}

json_value_t *json_null(void) { return alloc_value(JSON_NULL); }

json_value_t *json_bool(int b)
{
    json_value_t *v = alloc_value(JSON_BOOL);
    if (v) v->boolean = b ? 1 : 0;
    return v;
}

json_value_t *json_number(double n)
{
    json_value_t *v = alloc_value(JSON_NUMBER);
    if (v) v->number = n;
    return v;
}

json_value_t *json_string(const char *s)
{
    json_value_t *v = alloc_value(JSON_STRING);
    if (!v) return NULL;
    v->string = sstrdup(s ? s : "");
    return v;
}

json_value_t *json_array(void) { return alloc_value(JSON_ARRAY); }
json_value_t *json_object(void) { return alloc_value(JSON_OBJECT); }

void json_free(json_value_t *v)
{
    if (!v) return;
    for (size_t i = 0; i < v->count; i++) {
        if (v->keys) free(v->keys[i]);
        json_free(v->items[i]);
    }
    free(v->items);
    free(v->keys);
    free(v->string);
    free(v);
}

void json_free_shallow(json_value_t *v)
{
    if (!v) return;
    free(v->items);
    free(v->keys);
    free(v->string);
    free(v);
}

static void grow(json_value_t *v)
{
    if (v->count < v->capacity) return;
    size_t want = v->capacity ? v->capacity * 2 : 8;
    json_value_t **it = realloc(v->items, want * sizeof(*it));
    if (!it) return;
    v->items = it;
    if (v->type == JSON_OBJECT) {
        char **ks = realloc(v->keys, want * sizeof(*ks));
        if (ks) v->keys = ks;
    }
    v->capacity = want;
}

void json_array_push(json_value_t *arr, json_value_t *item)
{
    if (!arr || arr->type != JSON_ARRAY) { json_free(item); return; }
    grow(arr);
    if (!arr->items) { json_free(item); return; }
    arr->items[arr->count++] = item;
}

void json_object_set(json_value_t *obj, const char *key, json_value_t *value)
{
    if (!obj || obj->type != JSON_OBJECT) { json_free(value); return; }
    /* Replace an existing key rather than duplicating it. */
    for (size_t i = 0; i < obj->count; i++) {
        if (obj->keys && strcmp(obj->keys[i], key) == 0) {
            json_free(obj->items[i]);
            obj->items[i] = value;
            return;
        }
    }
    grow(obj);
    if (!obj->items || !obj->keys) { json_free(value); return; }
    obj->keys[obj->count] = sstrdup(key);
    obj->items[obj->count] = value;
    obj->count++;
}

void json_object_set_str(json_value_t *obj, const char *key, const char *value)
{
    json_object_set(obj, key, json_string(value));
}

void json_object_set_num(json_value_t *obj, const char *key, double value)
{
    json_object_set(obj, key, json_number(value));
}

json_value_t *json_get(const json_value_t *obj, const char *key)
{
    if (!obj || obj->type != JSON_OBJECT || !obj->keys) return NULL;
    for (size_t i = 0; i < obj->count; i++)
        if (strcmp(obj->keys[i], key) == 0) return obj->items[i];
    return NULL;
}

const char *json_get_str(const json_value_t *obj, const char *key)
{
    json_value_t *v = json_get(obj, key);
    return (v && v->type == JSON_STRING) ? v->string : NULL;
}

double json_get_num(const json_value_t *obj, const char *key, double fallback)
{
    json_value_t *v = json_get(obj, key);
    return (v && v->type == JSON_NUMBER) ? v->number : fallback;
}

json_value_t *json_at(const json_value_t *arr, size_t index)
{
    if (!arr || index >= arr->count) return NULL;
    return arr->items[index];
}

size_t json_len(const json_value_t *v) { return v ? v->count : 0; }

const char *json_str_at(const json_value_t *arr, size_t index)
{
    json_value_t *v = json_at(arr, index);
    return (v && v->type == JSON_STRING) ? v->string : NULL;
}

/* --- escaping --- */

size_t json_escape(const char *in, char *out, size_t outlen)
{
    size_t o = 0;
    if (!outlen) return 0;
    if (!in) { out[0] = '\0'; return 0; }
    for (size_t i = 0; in[i]; i++) {
        unsigned char c = (unsigned char)in[i];
        char tmp[8];
        const char *piece = NULL;
        size_t need;
        switch (c) {
            case '"':  piece = "\\\""; break;
            case '\\': piece = "\\\\"; break;
            case '\n': piece = "\\n";  break;
            case '\r': piece = "\\r";  break;
            case '\t': piece = "\\t";  break;
            case '\b': piece = "\\b";  break;
            case '\f': piece = "\\f";  break;
            default:
                if (c < 0x20) {
                    snprintf(tmp, sizeof(tmp), "\\u%04x", c);
                    piece = tmp;
                } else {
                    tmp[0] = (char)c;
                    tmp[1] = '\0';
                    piece = tmp;
                }
        }
        need = strlen(piece);
        if (o + need >= outlen) break;   /* truncate safely, never overflow */
        memcpy(out + o, piece, need);
        o += need;
    }
    out[o] = '\0';
    return o;
}

/* --- serialization --- */

static void dump_string(const char *s, FILE *f)
{
    fputc('"', f);
    char esc[8];
    for (size_t i = 0; s && s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n", f);  break;
            case '\r': fputs("\\r", f);  break;
            case '\t': fputs("\\t", f);  break;
            default:
                if (c < 0x20) {
                    json_escape((const char[]){ (char)c, '\0' }, esc, sizeof(esc));
                    fputs(esc, f);
                } else {
                    fputc((char)c, f);
                }
        }
    }
    fputc('"', f);
}

/* The serializer writes through a FILE* so log/stream output is a plain fputc
 * path, but json_dump() must not depend on open_memstream(), which is POSIX
 * rather than C99. A tmpfile() on the local stub is both portable and fast
 * enough for report-sized documents. */
static FILE *open_scratch(void)
{
    FILE *f = tmpfile();
    if (!f) return NULL;
    return f;
}

void json_dump_to(const json_value_t *v, FILE *f, int indent, int depth)
{
    if (!v) { fputs("null", f); return; }
    const char *nl = indent ? "\n" : "";
    const char *pad = "";
    char padbuf[64] = "";
    if (indent) {
        int w = indent * (depth + 1);
        if (w < 60) { memset(padbuf, ' ', (size_t)w); padbuf[w] = '\0'; pad = padbuf; }
    }

    switch (v->type) {
        case JSON_NULL:   fputs("null", f); break;
        case JSON_BOOL:   fputs(v->boolean ? "true" : "false", f); break;
        case JSON_NUMBER: {
            /* Emit integral values without a decimal point so ids and ports
             * stay comparable with the previous JSON output. */
            if (v->number == (double)(long long)v->number &&
                v->number < 1e15 && v->number > -1e15)
                fprintf(f, "%lld", (long long)v->number);
            else
                fprintf(f, "%g", v->number);
            break;
        }
        case JSON_STRING: dump_string(v->string, f); break;
        case JSON_ARRAY:
            if (!v->count) { fputs("[]", f); break; }
            fputs("[", f);
            for (size_t i = 0; i < v->count; i++) {
                fputs(nl, f); fputs(pad, f);
                json_dump_to(v->items[i], f, indent, depth + 1);
                if (i + 1 < v->count) fputc(',', f);
            }
            fputs(nl, f);
            fputs(depth ? padbuf : "", f);
            /* closing indent: one level less than children */
            if (indent) {
                int w = indent * depth;
                memset(padbuf, ' ', (size_t)(w < 60 ? w : 59));
                padbuf[w < 60 ? w : 59] = '\0';
                fputs(padbuf, f);
            }
            fputc(']', f);
            break;
        case JSON_OBJECT:
            if (!v->count) { fputs("{}", f); break; }
            fputs("{", f);
            for (size_t i = 0; i < v->count; i++) {
                fputs(nl, f); fputs(pad, f);
                dump_string(v->keys ? v->keys[i] : "", f);
                fputc(':', f);
                if (indent) fputc(' ', f);
                json_dump_to(v->items[i], f, indent, depth + 1);
                if (i + 1 < v->count) fputc(',', f);
            }
            fputs(nl, f);
            if (indent) {
                int w = indent * depth;
                memset(padbuf, ' ', (size_t)(w < 60 ? w : 59));
                padbuf[w < 60 ? w : 59] = '\0';
                fputs(padbuf, f);
            }
            fputc('}', f);
            break;
    }
}

char *json_dump(const json_value_t *v, int indent)
{
    FILE *f = open_scratch();
    if (!f) return NULL;
    json_dump_to(v, f, indent, 0);

    long sz = ftell(f);
    if (sz < 0) { fclose(f); return sstrdup(""); }
    rewind(f);
    char *out = malloc((size_t)sz + 1);
    if (!out) { fclose(f); return NULL; }
    size_t got = fread(out, 1, (size_t)sz, f);
    out[got] = '\0';
    fclose(f);
    return out;
}

/* --- parser --- */

typedef struct {
    const char *p;
    const char *end;
    int depth;
} parser_t;

static void skip_ws(parser_t *ps)
{
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' ||
                               *ps->p == '\n' || *ps->p == '\r')) ps->p++;
}

static json_value_t *parse_value(parser_t *ps);

static int parse_hex4(const char *s, unsigned *out)
{
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = s[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return 0;
    }
    *out = v;
    return 1;
}

static char *parse_string_raw(parser_t *ps)
{
    if (ps->p >= ps->end || *ps->p != '"') return NULL;
    ps->p++;
    buf_t b; buf_init(&b);
    while (ps->p < ps->end && *ps->p != '"') {
        if (*ps->p == '\\') {
            ps->p++;
            if (ps->p >= ps->end) break;
            switch (*ps->p) {
                case 'n': buf_putc(&b, '\n'); break;
                case 't': buf_putc(&b, '\t'); break;
                case 'r': buf_putc(&b, '\r'); break;
                case 'b': buf_putc(&b, '\b'); break;
                case 'f': buf_putc(&b, '\f'); break;
                case '/': buf_putc(&b, '/');  break;
                case '"': buf_putc(&b, '"');  break;
                case '\\': buf_putc(&b, '\\'); break;
                case 'u': {
                    unsigned cp = 0;
                    if (ps->p + 4 < ps->end && parse_hex4(ps->p + 1, &cp)) {
                        ps->p += 4;
                        /* UTF-8 encode; surrogate pairs are not needed by
                         * any endpoint Sentinel consumes. */
                        if (cp < 0x80) buf_putc(&b, (char)cp);
                        else if (cp < 0x800) {
                            buf_putc(&b, (char)(0xC0 | (cp >> 6)));
                            buf_putc(&b, (char)(0x80 | (cp & 0x3F)));
                        } else {
                            buf_putc(&b, (char)(0xE0 | (cp >> 12)));
                            buf_putc(&b, (char)(0x80 | ((cp >> 6) & 0x3F)));
                            buf_putc(&b, (char)(0x80 | (cp & 0x3F)));
                        }
                    }
                    break;
                }
                default: buf_putc(&b, *ps->p);
            }
            ps->p++;
        } else {
            buf_putc(&b, *ps->p++);
        }
    }
    if (ps->p < ps->end) ps->p++;  /* closing quote */
    return buf_release(&b);
}

static json_value_t *parse_value(parser_t *ps)
{
    if (++ps->depth > 64) { ps->depth--; return NULL; }  /* bound recursion */
    skip_ws(ps);
    json_value_t *v = NULL;

    if (ps->p >= ps->end) { ps->depth--; return NULL; }

    switch (*ps->p) {
        case '{': {
            ps->p++;
            v = json_object();
            skip_ws(ps);
            if (ps->p < ps->end && *ps->p == '}') { ps->p++; break; }
            int closed = 0;
            while (ps->p < ps->end) {
                skip_ws(ps);
                char *k = parse_string_raw(ps);
                if (!k) break;
                skip_ws(ps);
                if (ps->p >= ps->end || *ps->p != ':') { free(k); break; }
                ps->p++;
                json_value_t *val = parse_value(ps);
                if (!val) { free(k); break; }
                json_object_set(v, k, val);
                free(k);
                skip_ws(ps);
                if (ps->p < ps->end && *ps->p == ',') { ps->p++; continue; }
                if (ps->p < ps->end && *ps->p == '}') { ps->p++; closed = 1; break; }
                break;
            }
            /* An unterminated object means the response was truncated. Failing
             * here matters: a half-parsed feed would otherwise be handed to the
             * caller as a valid-looking object with fewer entries, which reads
             * as "nothing found" rather than "the download was incomplete". */
            if (!closed) { json_free(v); return NULL; }
            break;
        }
        case '[': {
            ps->p++;
            v = json_array();
            skip_ws(ps);
            if (ps->p < ps->end && *ps->p == ']') { ps->p++; break; }
            int closed = 0;
            while (ps->p < ps->end) {
                json_value_t *item = parse_value(ps);
                if (!item) break;
                json_array_push(v, item);
                skip_ws(ps);
                if (ps->p < ps->end && *ps->p == ',') { ps->p++; continue; }
                if (ps->p < ps->end && *ps->p == ']') { ps->p++; closed = 1; break; }
                break;
            }
            if (!closed) { json_free(v); return NULL; }
            break;
        }
        case '"': {
            char *s = parse_string_raw(ps);
            if (s) { v = alloc_value(JSON_STRING); if (v) v->string = s; else free(s); }
            break;
        }
        case 't':
            if (ps->end - ps->p >= 4 && strncmp(ps->p, "true", 4) == 0) {
                ps->p += 4; v = json_bool(1);
            }
            break;
        case 'f':
            if (ps->end - ps->p >= 5 && strncmp(ps->p, "false", 5) == 0) {
                ps->p += 5; v = json_bool(0);
            }
            break;
        case 'n':
            if (ps->end - ps->p >= 4 && strncmp(ps->p, "null", 4) == 0) {
                ps->p += 4; v = json_null();
            }
            break;
        default: {
            char *endp = NULL;
            double d = strtod(ps->p, &endp);
            if (endp && endp != ps->p) { ps->p = endp; v = json_number(d); }
            break;
        }
    }
    ps->depth--;
    return v;
}

json_value_t *json_parse(const char *text, size_t len)
{
    if (!text) return NULL;
    parser_t ps = { text, text + len, 0 };
    json_value_t *v = parse_value(&ps);
    if (!v) return NULL;
    /* Trailing garbage is tolerated: some endpoints append newlines. */
    return v;
}
