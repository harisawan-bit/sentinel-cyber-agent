/* sentinel/util.h — crypto, HTTP, process, and filesystem helpers.
 *
 * Grouped in one header because the plugins are the consumers and each of
 * these is a leaf utility with no further dependencies.
 */
#ifndef SENTINEL_UTIL_H
#define SENTINEL_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* ---- SHA-256 (FIM baselines, canary integrity) ---- */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  data[64];
    size_t   datalen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);

/* Hash a whole file. Returns malloc'd lowercase hex, or NULL on failure. */
char *sha256_file_hex(const char *path);
/* Hash a buffer. out must hold 65 bytes. */
void sha256_hex(const void *data, size_t len, char *out);

/* ---- entropy ---- */
void random_bytes(uint8_t *out, size_t n);
char *random_hex(size_t nbytes);

/* ---- HTTP(S) ---- */
typedef struct {
    int   status;
    char *body;
    size_t body_len;
    char  content_type[128];
} http_resp;

/* GET `url` following no redirects. Returns 0 on success, non-zero on
 * transport failure. Fills *out (caller frees with http_resp_free).
 * For http:// the body is capped at 4 MiB. */
int  http_get(const char *url, http_resp *out, int timeout_sec);
void http_resp_free(http_resp *r);

/* Escape a URL query parameter value (percent-encode). Caller frees. */
char *url_encode(const char *s);

/* ---- processes ---- */
/* Run argv, capture stdout up to `max` bytes. Returns exit status, or -1. */
int proc_run(char *const argv[], char *out, size_t out_len, int timeout_sec);
/* Run and capture stdout, returning malloc'd NUL-terminated output. */
char *proc_capture(char *const argv[], size_t *out_len, int timeout_sec);

/* ---- filesystem ---- */
int   file_exists(const char *path);
long  file_size(const char *path);
char *read_file(const char *path, size_t *len);   /* malloc'd, NUL-terminated */
int   write_file(const char *path, const char *data, size_t len);
/* Read a /proc/sys style single-line value. Caller frees. */
char *read_sysctl(const char *path);

/* ---- time ---- */
double now_seconds(void);
void   iso8601(double t, char *out, size_t outlen);

/* ---- net ---- */
/* Resolve a hostname to a dotted-quad. Returns 0 on success. */
int  resolve_ipv4(const char *host, char *out, size_t outlen);
/* TCP connect with timeout. Returns the socket fd or -1. */
int  tcp_connect(const char *host, int port, int timeout_sec);
/* TLS connect over an existing fd. Returns an SSL* or NULL. */
void *tls_connect(int fd, const char *host, int verify, int timeout_sec);
void  tls_close(void *ssl, int fd);
/* Read a full HTTP response from an fd (plain or SSL) into an http_resp. */
int  http_read_response(int fd, void *ssl, http_resp *out);
/* Write a request and read the reply. */
int  http_do(const char *host, int port, const char *path, int use_tls,
             int verify, int timeout_sec, http_resp *out);

#endif /* SENTINEL_UTIL_H */
