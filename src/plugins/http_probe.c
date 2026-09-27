/* http_probe.c — native HTTP(S) reachability probe + tech fingerprint.
 *
 * Ported from sentinel/core/plugins/http_probe_plugin.py. That version had
 * already been rewritten onto the stdlib (urllib, no `requests`) so it stays
 * dependency-free after the port: http_do() in core/net.c is the only
 * transport, and no external engine is required.
 *
 * Behaviour deliberately preserved from the Python:
 *   - the target is reduced to a bare host (scheme, path and port stripped),
 *     then BOTH https:// and http:// are probed in that order, each producing
 *     its own finding;
 *   - redirects are not followed, so a 301/302 is a recon result, not a hop;
 *   - _SEV_BY_CODE is a sparse table; any status Python did not list is INFO.
 */
#include "sentinel/sentinel.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME          "http-probe"
#define PROBE_TIMEOUT 15

/* Window of the body scanned for <title> and CMS fingerprints; matches
 * Python's r.text[:2000] slice. */
#define BODY_SNIP 2000
/* Python truncated the tech list to 8 so report rows stay readable. */
#define TECH_MAX 8

/* HttpProbePlugin._SEV_BY_CODE */
static const struct { int code; severity_t sev; } SEV_BY_CODE[] = {
    { 200, SEV_INFO   }, { 301, SEV_LOW    }, { 302, SEV_LOW    },
    { 401, SEV_LOW    }, { 403, SEV_LOW    }, { 404, SEV_LOW    },
    { 500, SEV_MEDIUM }, { 502, SEV_MEDIUM }, { 503, SEV_MEDIUM },
};

static severity_t sev_for(int code)
{
    for (size_t i = 0; i < sizeof(SEV_BY_CODE) / sizeof(SEV_BY_CODE[0]); i++)
        if (SEV_BY_CODE[i].code == code) return SEV_BY_CODE[i].sev;
    return SEV_INFO;
}

/* strcasestr is a GNU extension and is banned by the porting contract, so the
 * two case-insensitive scans the Python used with re.I are done by hand. */
static const char *find_ci(const char *hay, size_t hlen, const char *needle)
{
    size_t n = strlen(needle);
    if (!n || hlen < n) return NULL;
    for (size_t i = 0; i + n <= hlen; i++) {
        size_t k = 0;
        while (k < n &&
               tolower((unsigned char)hay[i + k]) == tolower((unsigned char)needle[k]))
            k++;
        if (k == n) return hay + i;
    }
    return NULL;
}

/* Replicates re.search(r"<title>(.*?)</title>", snip, re.I).group(1).
 * The scan stops at a newline because Python's `.` does not match one, so a
 * <title> split across lines is not a match there either. */
static char *extract_title(const char *body, size_t snip_len)
{
    if (!body) return NULL;
    const char *end = body + snip_len;
    const char *open = find_ci(body, snip_len, "<title>");
    if (!open) return NULL;

    const char *start = open + strlen("<title>");
    for (const char *p = start; p < end && *p != '\n'; p++) {
        size_t left = (size_t)(end - p);
        if (left < 8) break;
        if (tolower((unsigned char)p[0]) == '<' && tolower((unsigned char)p[1]) == '/' &&
            tolower((unsigned char)p[2]) == 't' && tolower((unsigned char)p[3]) == 'i' &&
            tolower((unsigned char)p[4]) == 't' && tolower((unsigned char)p[5]) == 'l' &&
            tolower((unsigned char)p[6]) == 'e' && tolower((unsigned char)p[7]) == '>')
            return sstrndup(start, (size_t)(p - start));
    }
    return NULL;
}

/* Strip scheme, path and port. Python did host.split("/")[0].split(":")[0]
 * after removing a known scheme prefix, which is a cut at the earliest of the
 * two separators. */
static void host_of(const char *target, char *out, size_t outlen)
{
    const char *h = target;
    if (strncmp(h, "https://", 8) == 0)      h += 8;
    else if (strncmp(h, "http://", 7) == 0) h += 7;

    const char *slash = strchr(h, '/');
    size_t len = slash ? (size_t)(slash - h) : strlen(h);
    const char *colon = memchr(h, ':', len);
    if (colon) len = (size_t)(colon - h);
    if (len >= outlen) len = outlen - 1;
    memcpy(out, h, len);
    out[len] = '\0';
}

static int run(orchestrator_t *ctx, const char *target)
{
    char host[256];
    host_of(target, host, sizeof(host));

    /* Python short-circuited the whole probe on gethostbyname() failure so a
     * typo'd target does not cost two connection timeouts. */
    char ip[64];
    if (resolve_ipv4(host, ip, sizeof(ip)) != 0) {
        char v[320];
        snprintf(v, sizeof(v), "DNS resolution failed for %s", host);
        orch_note(ctx, NAME, v, target, NULL);
        return 0;
    }

    for (int i = 0; i < 2; i++) {
        int use_tls = (i == 0);
        const char *scheme = use_tls ? "https" : "http";
        int port = use_tls ? 443 : 80;

        char url[272];
        snprintf(url, sizeof(url), "%s://%s", scheme, host);

        /* memset because http_do() leaves *out untouched on its -1/-2 paths,
         * and http_resp_free() runs unconditionally below. */
        http_resp resp;
        memset(&resp, 0, sizeof(resp));
        int rc = http_do(host, port, "/", use_tls, /*verify=*/1, PROBE_TIMEOUT, &resp);
        if (rc != 0) {
            /* -2 is a TLS handshake failure (bad chain, expired cert, plain
             * HTTP on 443). Both are notes in Python too: it caught the
             * exception and emitted severity="info" before trying the next
             * scheme. */
            const char *why = (rc == -2) ? "TLS handshake failed"
                                         : "connection failed";
            char v[320];
            snprintf(v, sizeof(v), "%s probe error: %s", scheme, why);
            orch_note(ctx, NAME, v, target, NULL);
            http_resp_free(&resp);
            continue;
        }

        size_t snip = resp.body_len < BODY_SNIP ? resp.body_len : BODY_SNIP;

        json_value_t *tech = json_array();
        /* re.search(r"wordpress", body_snip, re.I). The header-derived hints
         * (Server, X-Powered-By, X-AspNet-Version, X-Generator, Set-Cookie) and
         * the Cloudflare Cf-Ray check are not portable: http_resp exposes only
         * status, body and content_type, so the tech list carries what can be
         * derived from the body. content_type is recorded separately below. */
        if (find_ci(resp.body, snip, "wordpress")) {
            json_value_t *t = json_array();
            json_array_push(t, json_string("CMS=WordPress"));
            for (size_t k = 0; k < json_len(tech) && k < TECH_MAX; k++)
                json_array_push(tech, json_at(t, k));
            json_free(t);
        }

        char *title = extract_title(resp.body, snip);

        json_value_t *meta = json_object();
        json_object_set_num(meta, "status_code", (double)resp.status);
        if (title) {
            json_object_set_str(meta, "title", title);
            free(title);
        } else {
            json_object_set(meta, "title", json_null());
        }
        json_object_set(meta, "tech", tech);
        json_object_set_str(meta, "content_type", resp.content_type);

        char detail[64];
        snprintf(detail, sizeof(detail), "HTTP %d", resp.status);

        finding_t *f = finding_new(NAME, FT_HOST, url, target, sev_for(resp.status));
        if (f) {
            finding_set_detail(f, detail);
            finding_set_meta(f, meta);
            orch_add(ctx, f);
        } else {
            json_free(meta);
        }
        http_resp_free(&resp);
    }
    return 0;
}

const plugin_t http_probe_plugin = {
    "http-probe",
    "Native HTTP probe + header/tech fingerprint (first-party MIT)",
    STAGE_RECON,
    { NULL },
    run
};
