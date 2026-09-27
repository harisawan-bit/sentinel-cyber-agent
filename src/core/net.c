/* net.c — DNS, TCP, TLS, and HTTP.
 *
 * C99 has no TLS in the standard library, so this is the one subsystem that
 * links an external library. OpenSSL is used rather than vendoring mbedTLS so
 * the project keeps receiving distro security updates, and it is a link-time
 * dependency only: builds that never touch https still link fine.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/util.h"
#include "sentinel/buf.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#define MAX_BODY (4u * 1024u * 1024u)

/* strcasestr is a GNU extension, not C99. Header matching is done with this
 * instead so the build stays warning-clean under -std=c99 without _GNU_SOURCE. */
static const char *find_ci(const char *hay, const char *needle)
{
    if (!hay || !needle || !*needle) return NULL;
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] && needle[i] &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (i == nl) return p;
    }
    return NULL;
}

/* -------------------------------------------------------------- DNS / TCP */

int resolve_ipv4(const char *host, char *out, size_t outlen)
{
    if (!host || !outlen) return -1;
    /* Numeric address short-circuit: avoids a resolver round trip. */
    struct in_addr probe;
    if (inet_pton(AF_INET, host, &probe) == 1) {
        snprintf(out, outlen, "%s", host);
        return 0;
    }
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    int rc = inet_ntop(AF_INET, &sa->sin_addr, out, (socklen_t)outlen) ? 0 : -1;
    freeaddrinfo(res);
    return rc;
}

int tcp_connect(const char *host, int port, int timeout_sec)
{
    char ip[64];
    if (resolve_ipv4(host, ip, sizeof(ip)) != 0) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = { timeout_sec, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, ip, &sa.sin_addr);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ------------------------------------------------------------------- TLS */

static int g_ssl_init = 0;

static void ensure_ssl_init(void)
{
    if (g_ssl_init) return;
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    g_ssl_init = 1;
}

void *tls_connect(int fd, const char *host, int verify, int timeout_sec)
{
    (void)timeout_sec;
    ensure_ssl_init();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    if (verify) {
        /* Verify against the system trust store, but let a missing store
         * degrade to "unverified" rather than breaking scans entirely; the
         * plugin records which mode was used in its metadata. */
        if (!SSL_CTX_set_default_verify_paths(ctx)) {
            /* leave verification off, caller records tls_verified=false */
        } else {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        }
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); return NULL; }
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);
    if (verify) {
        X509_VERIFY_PARAM *p = SSL_get0_param(ssl);
        X509_VERIFY_PARAM_set_hostflags(p, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        X509_VERIFY_PARAM_set1_host(p, host, 0);
    }

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }
    /* Stash the CTX on the SSL object so tls_close can free it; OpenSSL does
     * not own a caller-supplied CTX. */
    SSL_set_ex_data(ssl, 0, ctx);
    return ssl;
}

void tls_close(void *ssl, int fd)
{
    if (ssl) {
        SSL_CTX *ctx = SSL_get_ex_data((SSL *)ssl, 0);
        SSL_shutdown((SSL *)ssl);
        SSL_free((SSL *)ssl);
        if (ctx) SSL_CTX_free(ctx);
    }
    if (fd >= 0) close(fd);
}

/* ------------------------------------------------------------------ HTTP */

static ssize_t io_read(int fd, void *ssl, void *buf, size_t n)
{
    if (ssl) return SSL_read((SSL *)ssl, buf, (int)n);
    return read(fd, buf, n);
}

static ssize_t io_write(int fd, void *ssl, const void *buf, size_t n)
{
    if (ssl) return SSL_write((SSL *)ssl, buf, (int)n);
    return write(fd, buf, n);
}

int http_read_response(int fd, void *ssl, http_resp *out)
{
    memset(out, 0, sizeof(*out));

    /* Read until end of headers. */
    buf_t raw; buf_init(&raw);
    char chunk[4096];
    size_t header_end = 0;
    char *hdr_end = NULL;

    for (int i = 0; i < 64; i++) {
        ssize_t r = io_read(fd, ssl, chunk, sizeof(chunk));
        if (r <= 0) break;
        buf_append(&raw, chunk, (size_t)r);
        hdr_end = strstr(raw.data, "\r\n\r\n");
        if (hdr_end) { header_end = (size_t)(hdr_end - raw.data) + 4; break; }
        if (raw.len > MAX_BODY) break;
    }
    if (!hdr_end) { buf_free(&raw); return -1; }

    /* Status line. */
    out->status = 0;
    if (strncmp(raw.data, "HTTP/1.", 7) == 0) {
        const char *sp = strchr(raw.data, ' ');
        if (sp) out->status = atoi(sp + 1);
    }
    /* Content-Type, if the server sent one. */
    const char *ct = find_ci(raw.data, "\nContent-Type:");
    if (ct) {
        /* "\nContent-Type:" is 14 characters, so the value starts at ct + 14. */
        const char *v = ct + 14;
        while (*v == ' ' || *v == '\t') v++;
        if (*v) {
            size_t n = strcspn(v, "\r\n");
            if (n >= sizeof(out->content_type)) n = sizeof(out->content_type) - 1;
            memcpy(out->content_type, v, n);
            out->content_type[n] = '\0';
        }
    }

    /* Transfer-Encoding: chunked needs decoding. */
    const char *te = find_ci(raw.data, "\nTransfer-Encoding:");
    int chunked = te && find_ci(te, "chunked") != NULL;

    size_t have = raw.len - header_end;
    if (chunked) {
        /* The first read almost never contains the whole body, so keep pulling
         * from the socket as the decoder runs out of buffered data. Decoding
         * only what arrived with the headers silently truncated large
         * responses — a chunked threat-intel feed came back as a few KB of
         * valid-looking JSON, which reads as "no results" rather than an error.
         */
        buf_t body; buf_init(&body);
        size_t p = header_end;   /* cursor into raw.data */

        for (;;) {
            /* Parse a chunk-size line at the cursor. */
            char szbuf[32];
            size_t o = 0;
            while (p + o < raw.len && raw.data[p + o] != '\r' && raw.data[p + o] != '\n' &&
                   o < sizeof(szbuf) - 1) {
                szbuf[o] = raw.data[p + o];
                o++;
            }
            if (p + o >= raw.len && o == 0) {
                /* Need more data for the size line. */
                ssize_t r = io_read(fd, ssl, chunk, sizeof(chunk));
                if (r <= 0) break;
                buf_append(&raw, chunk, (size_t)r);
                continue;
            }
            szbuf[o] = '\0';
            unsigned long csize = strtoul(szbuf, NULL, 16);
            p += o;
            /* consume CRLF after the size */
            while (p < raw.len && (raw.data[p] == '\r' || raw.data[p] == '\n')) p++;
            if (csize == 0) break;       /* terminal chunk */
            if (body.len + csize > MAX_BODY) break;

            /* Pull until this chunk is fully buffered. */
            while (raw.len < p + csize + 2) {
                ssize_t r = io_read(fd, ssl, chunk, sizeof(chunk));
                if (r <= 0) break;
                buf_append(&raw, chunk, (size_t)r);
            }
            size_t avail = (raw.len > p) ? raw.len - p : 0;
            if (avail < csize) {         /* truncated mid-chunk */
                if (avail) buf_append(&body, raw.data + p, avail);
                break;
            }
            buf_append(&body, raw.data + p, csize);
            p += csize;
            while (p < raw.len && (raw.data[p] == '\r' || raw.data[p] == '\n')) p++;
        }
        out->body = buf_release(&body);
    } else {
        buf_t body; buf_init(&body);
        buf_append(&body, raw.data + header_end, have);
        /* Content-Length says how much more to pull. */
        const char *cl = find_ci(raw.data, "\nContent-Length:");
        if (cl) {
            long want = atol(cl + 16);
            if (want > 0) {
                while ((long)body.len < want) {
                    ssize_t r = io_read(fd, ssl, chunk, sizeof(chunk));
                    if (r <= 0) break;
                    buf_append(&body, chunk, (size_t)r);
                    if (body.len > MAX_BODY) break;
                }
                if (body.len > (size_t)want) body.len = (size_t)want;
            }
        } else {
            /* No length header: read until close. */
            while (body.len < MAX_BODY) {
                ssize_t r = io_read(fd, ssl, chunk, sizeof(chunk));
                if (r <= 0) break;
                buf_append(&body, chunk, (size_t)r);
            }
        }
        out->body = buf_release(&body);
    }
    out->body_len = out->body ? strlen(out->body) : 0;
    buf_free(&raw);
    return 0;
}

int http_do(const char *host, int port, const char *path, int use_tls,
            int verify, int timeout_sec, http_resp *out)
{
    int fd = tcp_connect(host, port, timeout_sec);
    if (fd < 0) return -1;

    void *ssl = NULL;
    if (use_tls) {
        ssl = tls_connect(fd, host, verify, timeout_sec);
        if (!ssl) { close(fd); return -2; }
    }

    buf_t req; buf_init(&req);
    buf_printf(&req,
               "GET %s HTTP/1.1\r\n"
               "Host: %s\r\n"
               "User-Agent: Sentinel/%s\r\n"
               "Accept: */*\r\n"
               "Connection: close\r\n\r\n",
               path ? path : "/", host, "2.5.0");

    ssize_t w = io_write(fd, ssl, req.data, req.len);
    buf_free(&req);
    if (w <= 0) { tls_close(ssl, fd); return -1; }

    int rc = http_read_response(fd, ssl, out);
    tls_close(ssl, fd);
    return rc;
}

int http_get(const char *url, http_resp *out, int timeout_sec)
{
    if (!url || strncmp(url, "http://", 7) != 0) return -1;

    const char *rest = url + 7;
    char host[256];
    const char *slash = strchr(rest, '/');
    const char *colon = strchr(rest, ':');

    /* Path defaults to "/". */
    const char *path = "/";
    if (slash) path = slash;

    size_t hlen;
    if (colon && (!slash || colon < slash)) hlen = (size_t)(colon - rest);
    else hlen = slash ? (size_t)(slash - rest) : strlen(rest);

    if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
    memcpy(host, rest, hlen);
    host[hlen] = '\0';

    int port = 80;
    if (colon && (!slash || colon < slash)) port = atoi(colon + 1);
    return http_do(host, port, path, 0, 0, timeout_sec, out);
}
