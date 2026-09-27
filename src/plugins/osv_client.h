/* osv_client.h — shared OSV.dev query helper for the scan-stage plugins.
 *
 * Both osv_correlate and pkg_audit hit https://api.osv.dev/v1/query, and the
 * porting contract names http_do() as the transport. http_do() is GET-only,
 * though, and OSV answers GET /v1/query with HTTP 405 "method is not allowed"
 * (verified against the live API) — the endpoint takes POST with a JSON body,
 * which is what the Python plugins used. So the request is assembled here from
 * the primitives util.h does expose: tcp_connect(), tls_connect(),
 * http_read_response(). One shared static helper beats duplicating it.
 *
 * Header-only and static on purpose: each plugin .c still compiles in
 * isolation, and there is no link-time symbol for the registry to collide on.
 */
#ifndef SENTINEL_PLUGINS_OSV_CLIENT_H
#define SENTINEL_PLUGINS_OSV_CLIENT_H

#include "sentinel/sentinel.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

#define OSV_HOST "api.osv.dev"
#define OSV_PATH "/v1/query"

/* Why the caller saw no vulns, so it can decide between "nothing to report"
 * and "worth a note in the report". */
typedef enum {
    OSV_OK = 0,          /* parsed, and a vulns array was present (possibly empty) */
    OSV_TRANSPORT_FAIL,  /* no HTTP response at all: DNS/TCP/TLS/timeout */
    OSV_BAD_RESPONSE     /* a response arrived but was not the documented shape */
} osv_result_t;

/* Build the query body. Package names come from /var/lib/dpkg/status, i.e.
 * outside our control, so every value is escaped before it is embedded.
 * json_escape() escapes the *contents* of a string, so the surrounding quotes
 * are ours to add. */
static inline char *osv_json_body(const char *ecosystem, const char *name,
                                  const char *version)
{
    buf_t b;
    char esc[2048];

    buf_init(&b);
    if (version && *version) {
        /* Python _query_osv_pkg puts "version" ahead of "package". */
        buf_puts(&b, "{\"version\":\"");
        json_escape(version, esc, sizeof esc);
        buf_puts(&b, esc);
        buf_puts(&b, "\",\"package\":{\"ecosystem\":\"");
    } else {
        buf_puts(&b, "{\"package\":{\"ecosystem\":\"");
    }
    json_escape(ecosystem ? ecosystem : "", esc, sizeof esc);
    buf_puts(&b, esc);
    buf_puts(&b, "\",\"name\":\"");
    json_escape(name ? name : "", esc, sizeof esc);
    buf_puts(&b, esc);
    buf_puts(&b, "\"}}");
    return buf_release(&b);
}

/* POST `body` to OSV and return the response body (caller frees). NULL on
 * transport failure. */
static inline char *osv_post(const char *body, int timeout_sec, int *status)
{
    if (status) *status = 0;

    int fd = tcp_connect(OSV_HOST, 443, timeout_sec);
    if (fd < 0) return NULL;

    /* verify=1: Python's urllib validated the api.osv.dev chain, and an
     * unverified lookup feed would let a MITM choose which CVEs we report. */
    void *ssl = tls_connect(fd, OSV_HOST, 1, timeout_sec);
    if (!ssl) { tls_close(NULL, fd); return NULL; }

    buf_t req;
    buf_init(&req);
    buf_printf(&req,
               "POST %s HTTP/1.1\r\n"
               "Host: %s\r\n"
               "User-Agent: Sentinel/%s\r\n"
               "Accept: application/json\r\n"
               "Content-Type: application/json\r\n"
               "Content-Length: %lu\r\n"
               "Connection: close\r\n\r\n",
               OSV_PATH, OSV_HOST, SENTINEL_VERSION, (unsigned long)strlen(body));
    buf_append(&req, body, strlen(body));

    int sent = SSL_write((SSL *)ssl, req.data, (int)req.len);
    buf_free(&req);
    if (sent <= 0) { tls_close(ssl, fd); return NULL; }

    http_resp resp;
    int rc = http_read_response(fd, ssl, &resp);
    tls_close(ssl, fd);
    if (rc != 0) return NULL;

    if (status) *status = resp.status;
    /* Body ownership passes to the caller; http_resp_free would free it. */
    char *out = resp.body;
    resp.body = NULL;
    resp.body_len = 0;
    http_resp_free(&resp);
    return out;
}

/* Python _SEV_ORDER. `dflt` is the caller's starting severity: INFO in
 * osv_correlate, MEDIUM in pkg_audit. Unrecognised labels keep the default,
 * which is what a dict .get(label, sev) does. */
static inline severity_t osv_severity_from_label(const char *label, severity_t dflt)
{
    if (!label) return dflt;
    if (str_ieq(label, "LOW")) return SEV_LOW;
    if (str_ieq(label, "MODERATE") || str_ieq(label, "MEDIUM")) return SEV_MEDIUM;
    if (str_ieq(label, "HIGH")) return SEV_HIGH;
    if (str_ieq(label, "CRITICAL")) return SEV_CRITICAL;
    return dflt;
}

/* Resolve one vuln entry's severity. Shared by both plugins so the odd
 * behaviour below is documented once: OSV's "severity"[].score holds a CVSS
 * vector ("CVSS:3.1/AV:N/AC:L/..."), never a label, so that loop is a no-op
 * against the live API. The label that does land is database_specific.severity
 * (GitHub's HIGH/MEDIUM/LOW). Kept faithful to Python rather than "fixed" with
 * a CVSS base-score calculation, which would change every emitted severity. */
static inline severity_t osv_severity(const json_value_t *vuln, severity_t dflt)
{
    severity_t sev = dflt;

    const json_value_t *arr = json_get(vuln, "severity");
    for (size_t i = 0; i < json_len(arr); i++)
        sev = osv_severity_from_label(json_get_str(json_at(arr, i), "score"), sev);

    const json_value_t *db = json_get(vuln, "database_specific");
    const char *label = json_get_str(db, "severity");
    if (label) sev = osv_severity_from_label(label, sev);

    return sev;
}

/* Query one package. Returns the parsed response root (caller frees with
 * json_free) or NULL; *result distinguishes a dead network from a response we
 * could not make sense of. `version` may be NULL. */
static inline json_value_t *osv_query(const char *ecosystem, const char *name,
                                      const char *version, int timeout_sec,
                                      osv_result_t *result)
{
    char *body = osv_json_body(ecosystem, name, version);
    if (!body) { if (result) *result = OSV_BAD_RESPONSE; return NULL; }

    int status = 0;
    char *raw = osv_post(body, timeout_sec, &status);
    free(body);
    if (!raw) { if (result) *result = OSV_TRANSPORT_FAIL; return NULL; }

    json_value_t *root = json_parse(raw, strlen(raw));
    free(raw);
    if (!root) { if (result) *result = OSV_BAD_RESPONSE; return NULL; }

    /* A 200 with an empty object is OSV's way of saying "no advisories for this
     * package" — it is a successful, empty result, exactly what Python's
     * `.get("vulns", [])` produced, and must not be reported as a failure or
     * every clean package would raise a note. Only a non-200 or an unparseable
     * body is a genuine error: OSV answers those with {"code":..,"message":..}
     * or an HTML gateway page. */
    if (status != 200) {
        if (result) *result = OSV_BAD_RESPONSE;
        json_free(root);
        return NULL;
    }
    if (result) *result = OSV_OK;
    return root;
}

#endif /* SENTINEL_PLUGINS_OSV_CLIENT_H */
