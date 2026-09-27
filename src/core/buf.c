/* buf.c — growable byte buffer and string helpers. */
#include "sentinel/buf.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void buf_init(buf_t *b) { b->data = NULL; b->len = 0; b->cap = 0; }

void buf_free(buf_t *b) { free(b->data); b->data = NULL; b->len = b->cap = 0; }

void buf_reserve(buf_t *b, size_t extra)
{
    if (b->len + extra + 1 <= b->cap) return;
    size_t want = b->cap ? b->cap : 128;
    while (want < b->len + extra + 1) want *= 2;
    char *p = realloc(b->data, want);
    if (!p) { /* OOM: fail loudly rather than corrupt state silently. */
        fprintf(stderr, "[!] sentinel: out of memory growing buffer\n");
        abort();
    }
    b->data = p;
    b->cap = want;
}

void buf_append(buf_t *b, const char *data, size_t n)
{
    if (!n) return;
    buf_reserve(b, n);
    memcpy(b->data + b->len, data, n);
    b->len += n;
    b->data[b->len] = '\0';
}

void buf_puts(buf_t *b, const char *s) { if (s) buf_append(b, s, strlen(s)); }

void buf_putc(buf_t *b, char c) { buf_append(b, &c, 1); }

void buf_printf(buf_t *b, const char *fmt, ...)
{
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) { va_end(ap2); return; }
    buf_reserve(b, (size_t)n);
    vsnprintf(b->data + b->len, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)n;
}

char *buf_release(buf_t *b)
{
    if (!b->data) buf_reserve(b, 0);
    b->data[b->len] = '\0';
    char *p = b->data;
    b->data = NULL; b->len = b->cap = 0;
    return p;
}

char *sstrdup(const char *s)
{
    if (!s) return NULL;
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

char *sstrndup(const char *s, size_t n)
{
    char *p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

char *str_trim(char *s)
{
    if (!s) return s;
    char *start = s;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != s) memmove(s, start, strlen(start) + 1);
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    return s;
}

int str_contains(const char *hay, const char *needle)
{
    if (!hay || !needle) return 0;
    return strstr(hay, needle) != NULL;
}

int str_ieq(const char *a, const char *b)
{
    if (!a || !b) return a == b;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == *b;
}

void str_lower(const char *in, char *out, size_t outlen)
{
    if (!outlen) return;
    size_t i = 0;
    if (in) for (; in[i] && i + 1 < outlen; i++)
        out[i] = (char)tolower((unsigned char)in[i]);
    out[i] = '\0';
}

char *str_replace_all(const char *in, const char *from, const char *to)
{
    if (!in) return NULL;
    if (!from || !*from) return sstrdup(in);
    size_t flen = strlen(from), tlen = strlen(to);
    buf_t b; buf_init(&b);
    const char *p = in;
    while (*p) {
        if (strncmp(p, from, flen) == 0) {
            buf_append(&b, to, tlen);
            p += flen;
        } else {
            buf_putc(&b, *p++);
        }
    }
    return buf_release(&b);
}
