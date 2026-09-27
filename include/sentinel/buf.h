/* sentinel/buf.h — growable byte buffer and small string helpers.
 *
 * C99 has no dynamic strings. Nearly every ported subsystem needs one, and
 * getting the growth and truncation rules right once here beats repeating them.
 */
#ifndef SENTINEL_BUF_H
#define SENTINEL_BUF_H

#include <stddef.h>

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} buf_t;

void  buf_init(buf_t *b);
void  buf_free(buf_t *b);
void  buf_reserve(buf_t *b, size_t extra);
void  buf_append(buf_t *b, const char *data, size_t n);
void  buf_puts(buf_t *b, const char *s);
void  buf_putc(buf_t *b, char c);
void  buf_printf(buf_t *b, const char *fmt, ...);
/* Detach the NUL-terminated contents; caller owns the pointer. */
char *buf_release(buf_t *b);

/* strdup is POSIX, not C99, so provide it under a project name. */
char *sstrdup(const char *s);
char *sstrndup(const char *s, size_t n);
/* Trim ASCII whitespace in place; returns s. */
char *str_trim(char *s);
int   str_contains(const char *hay, const char *needle);
int   str_ieq(const char *a, const char *b);
/* Lowercase into a caller buffer (truncates safely). */
void  str_lower(const char *in, char *out, size_t outlen);
/* Replace every occurrence of `from` with `to`; returns malloc'd result. */
char *str_replace_all(const char *in, const char *from, const char *to);

#endif /* SENTINEL_BUF_H */
