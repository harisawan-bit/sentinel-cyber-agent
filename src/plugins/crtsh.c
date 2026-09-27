/* crtsh.c — subdomain discovery from Certificate Transparency logs.
 *
 * Ported from sentinel/core/plugins/crtsh_plugin.py. Pure first-party code:
 * it queries the public crt.sh JSON endpoint and needs no external engine, so
 * it fills the recon stage even when the projectdiscovery binaries are absent.
 *
 * The Python parsed the body with json.loads() and then called .get() on each
 * element, which assumed a JSON array of objects. crt.sh rate-limits and
 * occasionally answers with an object or an HTML error page, so every access
 * here is guarded: a non-array body becomes an informational note, not a crash.
 */
#include "sentinel/sentinel.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME     "crtsh"
#define CRTSH_HDR_NAME "crt.sh"
#define TIMEOUT  30

/* Case-insensitive tail comparison. str_endswith() does not exist and
 * strcasestr is a GNU extension banned by the porting contract. */
static int ends_with_ci(const char *s, size_t slen, const char *suffix)
{
    size_t n = strlen(suffix);
    if (slen < n) return 0;
    const char *tail = s + (slen - n);
    for (size_t i = 0; i < n; i++)
        if (tolower((unsigned char)tail[i]) != tolower((unsigned char)suffix[i]))
            return 0;
    return 1;
}

static int run(orchestrator_t *ctx, const char *target)
{
    /* Latent bug fixed, not reproduced: the Python did
     *
     *     domain = target.split("/")[0].split(":")[0]
     *     if domain.startswith("http"):
     *         domain = domain.split("://", 1)[1]
     *
     * so for "https://example.com" the first line already truncated the
     * string to "https", the startswith() branch then fired, and the
     * split("://") had no "://" left to split on -> IndexError on every
     * URL-shaped target. Verified: Python raises for both "http://" and
     * "https://" inputs. Stripping the scheme up front yields the bare host
     * the author clearly intended, and agrees with the Python on every input
     * it did not crash on. */
    char domain[256];
    const char *d = target;
    if (strncmp(d, "http://", 7) == 0)       d += 7;
    else if (strncmp(d, "https://", 8) == 0) d += 8;

    const char *slash = strchr(d, '/');
    size_t dlen = slash ? (size_t)(slash - d) : strlen(d);
    const char *colon = memchr(d, ':', dlen);
    if (colon) dlen = (size_t)(colon - d);
    if (dlen >= sizeof(domain)) dlen = sizeof(domain) - 1;
    memcpy(domain, d, dlen);
    domain[dlen] = '\0';

    if (!domain[0]) {
        orch_note(ctx, NAME, "crt.sh query skipped: no domain in target", target, NULL);
        return 0;
    }

    /* The domain is operator-supplied, not attacker-controlled, but it is
     * still interpolated into a URL — percent-encode so a stray '#' or '&'
     * cannot truncate or split the query. */
    char *enc = url_encode(domain);
    if (!enc) {
        orch_note(ctx, NAME, "crt.sh query failed: out of memory", target, NULL);
        return 0;
    }
    char path[512];
    snprintf(path, sizeof(path), "/?q=%s&output=json", enc);
    free(enc);

    http_resp resp;
    memset(&resp, 0, sizeof(resp));
    int rc = http_do(CRTSH_HDR_NAME, 443, path, /*use_tls=*/1, /*verify=*/1,
                     TIMEOUT, &resp);
    if (rc != 0) {
        char v[256];
        snprintf(v, sizeof(v), "crt.sh query failed: %s",
                 rc == -2 ? "TLS handshake failed" : "connection failed");
        orch_note(ctx, NAME, v, target, NULL);
        http_resp_free(&resp);
        return 0;
    }

    json_value_t *data = json_parse(resp.body ? resp.body : "", resp.body_len);
    http_resp_free(&resp);
    if (!data) {
        orch_note(ctx, NAME, "crt.sh query failed: malformed JSON response",
                  target, NULL);
        return 0;
    }
    if (data->type != JSON_ARRAY) {
        /* rate-limit pages and error objects land here; nothing to harvest. */
        json_free(data);
        orch_note(ctx, NAME, "crt.sh query returned an unexpected shape",
                  target, NULL);
        return 0;
    }

    /* Python used a set() for dedup. Subdomain counts per domain are small
     * (hundreds), so a sorted-array membership scan is cheaper than pulling in
     * a hash set and stays allocation-light. */
    char   **seen = NULL;
    size_t   seen_n = 0, seen_cap = 0;
    json_value_t *subs = json_array();

    for (size_t i = 0; i < json_len(data); i++) {
        json_value_t *entry = json_at(data, i);
        if (!entry || entry->type != JSON_OBJECT) continue;

        const char *name = json_get_str(entry, "name_value");
        if (!name) continue;

        /* crt.sh packs SANs into one newline-separated name_value field. */
        const char *p = name;
        while (*p) {
            const char *nl = strchr(p, '\n');
            size_t len = nl ? (size_t)(nl - p) : strlen(p);

            while (len && (*p == ' ' || *p == '\t' || *p == '\r')) { p++; len--; }
            while (len && (p[len - 1] == ' ' || p[len - 1] == '\t' || p[len - 1] == '\r'))
                len--;

            if (len && memchr(p, '*', len) == NULL) {
                char sub[256];
                if (len < sizeof(sub)) {
                    memcpy(sub, p, len);
                    sub[len] = '\0';
                    str_lower(sub, sub, sizeof(sub));

                    if (ends_with_ci(sub, strlen(sub), domain)) {
                        int dup = 0;
                        for (size_t k = 0; k < seen_n; k++)
                            if (strcmp(seen[k], sub) == 0) { dup = 1; break; }
                        if (!dup) {
                            if (seen_n == seen_cap) {
                                size_t cap = seen_cap ? seen_cap * 2 : 32;
                                char **g = realloc(seen, cap * sizeof(*seen));
                                if (!g) { json_free(subs);
                                          for (size_t k = 0; k < seen_n; k++) free(seen[k]);
                                          free(seen); json_free(data); return 0; }
                                seen = g;
                                seen_cap = cap;
                            }
                            seen[seen_n] = sstrdup(sub);
                            if (seen[seen_n]) {
                                json_array_push(subs, json_string(sub));
                                seen_n++;
                            }
                        }
                    }
                }
            }
            if (!nl) break;
            p = nl + 1;
        }
    }

    /* Python yields lazily, so a generator that the caller abandoned early
     * emitted only a prefix. C has to materialise; the finding set is the
     * same, just not streamed. */
    for (size_t i = 0; i < json_len(subs); i++) {
        const char *sub = json_str_at(subs, i);
        if (!sub) continue;
        finding_t *f = finding_new(NAME, FT_SUBDOMAIN, sub, target, SEV_INFO);
        if (f) orch_add(ctx, f);
    }

    for (size_t k = 0; k < seen_n; k++) free(seen[k]);
    free(seen);
    json_free(subs);
    json_free(data);
    return 0;
}

const plugin_t crtsh_plugin = {
    "crtsh",
    "Subdomain discovery via Certificate Transparency (crt.sh, no binary)",
    STAGE_RECON,
    { NULL },
    run
};
