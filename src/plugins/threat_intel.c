/* threat_intel.c — Threat intelligence correlation: CISA KEV + FIRST EPSS.
 *
 * Ported from sentinel/core/plugins/threat_intel_plugin.py.
 *
 * Correlates CVEs harvested from earlier findings against:
 *   1. CISA Known Exploited Vulnerabilities (KEV) — in-the-wild exploitation.
 *   2. FIRST EPSS — probability of exploitation within 30 days.
 *
 * Feed responses are attacker-influenced input: every field access is guarded
 * and no key is assumed to exist. Any transport error, non-2xx status, or
 * unexpected top-level shape degrades to an informational FT_NOTE — a scan
 * must never abort because a government feed is down or re-shaped its JSON.
 */
#include "sentinel/sentinel.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TI_TOOL        "threat_intel"
#define TI_FEED_TIMEOUT 8
#define TI_EPSS_BATCH  30     /* Python sliced cve_ids[:30] — preserved */
#define TI_EPSS_FLOOR  0.50
/* "CVE-" + 4 digits + "-" + up to 7 digits = 16 chars, plus the NUL.
 * Sized from the CVE pattern, not guessed. */
#define TI_CVE_MAX 18
/* Mirrors MAX_BODY in net.c. A body at the cap is almost certainly truncated,
 * and a truncated feed must not be treated as a complete one. */
#define TI_MAX_BODY    (4u * 1024u * 1024u)

/* A CISA KEV catalog truncated mid-body still parses as valid JSON, because
 * the object and its "vulnerabilities" array close early. Treating that
 * partial catalog as authoritative would silently report "not exploited in the
 * wild" for every CVE it happens to be missing — a false negative in exactly
 * the check that matters most here. The real catalog has held >1000 entries
 * since 2021, so a floor this low only ever rejects a broken fetch. */
#define TI_KEV_MIN_ENTRIES 100

#define TI_KEV_HOST    "www.cisa.gov"
#define TI_KEV_PATH    "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
#define TI_EPSS_HOST   "api.first.org"
#define TI_EPSS_PATH   "/data/v1/epss"

/* --- KEV catalog cache ---------------------------------------------------
 * The Python module cached this in a module global (_KEV_CACHE/_KEV_LOADED)
 * so a multi-target scan downloaded the multi-megabyte feed once. The catalog
 * is a property of the world, not of the target, so caching it does not make
 * the plugin unsafe to run against a different target immediately after; the
 * entries are intentionally retained for process lifetime rather than freed
 * after each target. No other plugin can observe or mutate this state. */
static char  **g_kev;
static size_t  g_kev_count;
static int     g_kev_loaded;

static int cmp_cve(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int kev_contains(const char *cve)
{
    if (!g_kev_count) return 0;
    const char *key = cve;
    return bsearch(&key, g_kev, g_kev_count, sizeof(*g_kev), cmp_cve) != NULL;
}

static void kev_add(char *cve)
{
    char **p = realloc(g_kev, (g_kev_count + 1) * sizeof(*g_kev));
    if (!p) { free(cve); return; }
    g_kev = p;
    g_kev[g_kev_count++] = cve;
}

/* Python: {v.get("cveID","").upper() for v in vulns if v.get("cveID")} */
static void kev_absorb(const json_value_t *vulns)
{
    for (size_t i = 0; i < json_len(vulns); i++) {
        const json_value_t *v = json_at(vulns, i);
        if (!v || v->type != JSON_OBJECT) continue;
        const char *id = json_get_str(v, "cveID");
        if (!id || !*id) continue;

        char *up = sstrdup(id);
        if (!up) continue;
        for (char *p = up; *p; p++)
            *p = (char)toupper((unsigned char)*p);
        kev_add(up);
    }
}

/* Returns 0 on success. On failure `*why` points to a static reason string. */
static int load_kev(const char **why)
{
    if (g_kev_loaded) return 0;
    g_kev_loaded = 1;   /* Python set _KEV_LOADED even on exception: no retry storm */

    http_resp resp;
    memset(&resp, 0, sizeof(resp));
    int rc = http_do(TI_KEV_HOST, 443, TI_KEV_PATH, 1, 1, TI_FEED_TIMEOUT, &resp);

    if (rc != 0) {
        *why = (rc == -2) ? "TLS handshake failed"
                          : "connection to the CISA KEV feed failed";
        return -1;
    }
    if (resp.status != 200) {
        *why = "the CISA KEV feed returned a non-200 status";
        http_resp_free(&resp);
        return -1;
    }
    if (!resp.body || resp.body_len == 0) {
        *why = "the CISA KEV feed returned an empty body";
        http_resp_free(&resp);
        return -1;
    }
    if (resp.body_len >= TI_MAX_BODY) {
        *why = "the CISA KEV feed body hit the 4 MiB transport cap and was truncated";
        http_resp_free(&resp);
        return -1;
    }

    json_value_t *doc = json_parse(resp.body, resp.body_len);
    http_resp_free(&resp);
    if (!doc) {
        *why = "the CISA KEV feed returned malformed JSON";
        return -1;
    }
    /* Python's data.get(...) would raise AttributeError on a non-dict and be
     * swallowed, yielding an empty catalog — same outcome, now visible. */
    if (doc->type != JSON_OBJECT) {
        json_free(doc);
        *why = "the CISA KEV feed JSON root was not an object";
        return -1;
    }

    /* A missing "vulnerabilities" key is an empty catalog, not an error —
     * Python's .get(key, []) defaulted the same way. */
    json_value_t *vulns = json_get(doc, "vulnerabilities");
    if (vulns && vulns->type == JSON_ARRAY) kev_absorb(vulns);

    if (g_kev_count) qsort(g_kev, g_kev_count, sizeof(*g_kev), cmp_cve);
    json_free(doc);

    if (g_kev_count < TI_KEV_MIN_ENTRIES) {
        /* Discard the partial set rather than correlating against it. */
        for (size_t i = 0; i < g_kev_count; i++) free(g_kev[i]);
        free(g_kev);
        g_kev = NULL;
        g_kev_count = 0;
        *why = "the CISA KEV feed returned an implausibly small catalog; "
               "the HTTP body was most likely truncated in transit";
        return -1;
    }
    return 0;
}

/* --- CVE harvesting ----------------------------------------------------- */

typedef struct {
    char  **v;
    size_t  n, cap;
} cve_set_t;

static void cve_free(cve_set_t *s)
{
    for (size_t i = 0; i < s->n; i++) free(s->v[i]);
    free(s->v);
    s->v = NULL;
    s->n = s->cap = 0;
}

static void cve_add(cve_set_t *s, const char *cve)
{
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->v[i], cve) == 0) return;   /* Python's set semantics */
    char *dup = sstrdup(cve);
    if (!dup) return;
    if (s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 16;
        char **p = realloc(s->v, cap * sizeof(*p));
        if (!p) { free(dup); return; }
        s->v = p;
        s->cap = cap;
    }
    s->v[s->n++] = dup;
}

static int is_digit_c(char c) { return c >= '0' && c <= '9'; }

static char lower_c(char c) { return (char)tolower((unsigned char)c); }

static int starts_with_ci(const char *s, const char *pfx, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (!s[i] || lower_c(s[i]) != lower_c(pfx[i])) return 0;
    return 1;
}

/* Equivalent of re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE).
 *
 * Python's \d{4,7} is greedy and unbounded at the tail, so an 8-digit sequence
 * yields the first 7 digits and scanning resumes right after — no word
 * boundary. That quirk is reproduced here rather than "fixed", because a CVE
 * ID is an opaque token and tightening it would change which findings match. */
static void scan_cves(const char *text, cve_set_t *out)
{
    if (!text) return;
    for (const char *p = text; *p; p++) {
        if (!starts_with_ci(p, "CVE-", 4)) continue;
        if (!is_digit_c(p[4]) || !is_digit_c(p[5]) || !is_digit_c(p[6]) || !is_digit_c(p[7]))
            continue;
        if (p[8] != '-') continue;

        const char *d = p + 9;
        size_t ndigits = 0;
        while (is_digit_c(d[ndigits])) ndigits++;
        if (ndigits < 4) continue;

        size_t take = ndigits > 7 ? 7 : ndigits;
        /* p[0..8] is "CVE-YYYY-", so 9 bytes covers the trailing dash; the
         * number is d[0..take). */
        char id[TI_CVE_MAX];
        memcpy(id, p, 9);
        memcpy(id + 9, d, take);
        id[9 + take] = '\0';
        for (size_t i = 0; i < 9 + take; i++)
            id[i] = (char)toupper((unsigned char)id[i]);
        cve_add(out, id);

        p += 8 + take;   /* resume exactly where Python's findall would */
    }
}

/* --- EPSS --------------------------------------------------------------- */

typedef struct {
    char    cve[TI_CVE_MAX];
    double  score;
    int     present;
} epss_row_t;

/* FIRST returns "epss" as a JSON string; Python's float() accepted either.
 * Returns 0 when the value cannot be read as a number, which makes the caller
 * skip the entry exactly as Python's `except (ValueError, TypeError)` did. */
static int parse_score(const json_value_t *entry, double *out)
{
    const json_value_t *v = json_get(entry, "epss");
    if (!v) { *out = 0.0; return 1; }   /* Python's .get("epss", 0.0) default */

    if (v->type == JSON_NUMBER) { *out = v->number; return 1; }
    if (v->type == JSON_STRING) {
        if (!v->string || !*v->string) return 0;
        char *endp = NULL;
        double d = strtod(v->string, &endp);
        if (endp && endp != v->string) { *out = d; return 1; }
    }
    return 0;
}

static int query_epss(char *const *cves, size_t n, epss_row_t *rows, const char **why)
{
    if (n == 0) return 0;
    if (n > TI_EPSS_BATCH) n = TI_EPSS_BATCH;

    buf_t path;
    buf_init(&path);
    buf_puts(&path, TI_EPSS_PATH "?cve=");
    for (size_t i = 0; i < n; i++) {
        if (i) buf_putc(&path, ',');
        buf_puts(&path, cves[i]);
    }

    http_resp resp;
    memset(&resp, 0, sizeof(resp));
    int rc = http_do(TI_EPSS_HOST, 443, path.data, 1, 1, TI_FEED_TIMEOUT, &resp);
    buf_free(&path);

    if (rc != 0) {
        *why = (rc == -2) ? "TLS handshake failed"
                          : "connection to the FIRST EPSS API failed";
        return -1;
    }
    if (resp.status != 200) {
        *why = "the FIRST EPSS API returned a non-200 status";
        http_resp_free(&resp);
        return -1;
    }
    if (!resp.body || resp.body_len == 0) {
        *why = "the FIRST EPSS API returned an empty body";
        http_resp_free(&resp);
        return -1;
    }

    json_value_t *doc = json_parse(resp.body, resp.body_len);
    http_resp_free(&resp);
    if (!doc) { *why = "the FIRST EPSS API returned malformed JSON"; return -1; }
    if (doc->type != JSON_OBJECT) {
        json_free(doc);
        *why = "the FIRST EPSS API JSON root was not an object";
        return -1;
    }

    json_value_t *data = json_get(doc, "data");
    if (data && data->type == JSON_ARRAY) {
        for (size_t i = 0; i < json_len(data); i++) {
            const json_value_t *entry = json_at(data, i);
            if (!entry || entry->type != JSON_OBJECT) continue;

            const char *cve = json_get_str(entry, "cve");
            if (!cve || !*cve) continue;

            double score;
            if (!parse_score(entry, &score)) continue;

            char up[TI_CVE_MAX];
            size_t len = strlen(cve);
            if (len >= sizeof(up)) len = sizeof(up) - 1;
            for (size_t k = 0; k < len; k++)
                up[k] = (char)toupper((unsigned char)cve[k]);
            up[len] = '\0';

            for (size_t r = 0; r < n; r++) {
                if (strcmp(rows[r].cve, up) != 0) continue;
                rows[r].score = score;
                rows[r].present = 1;
                break;
            }
        }
    }
    json_free(doc);
    return 0;
}

/* --- findings ----------------------------------------------------------- */

static void emit_kev(orchestrator_t *ctx, const char *target,
                     const char *cve, const epss_row_t *epss)
{
    buf_t v;
    buf_init(&v);
    buf_printf(&v, "CISA KEV Active Exploit: %s", cve);

    finding_t *f = finding_new(TI_TOOL, FT_VULNERABILITY, v.data, target, SEV_CRITICAL);
    buf_free(&v);
    if (!f) return;

    buf_t d;
    buf_init(&d);
    buf_printf(&d,
               "CRITICAL THREAT: %s is listed in CISA's Known Exploited Vulnerabilities catalog. "
               "Active in-the-wild weaponization confirmed by federal threat intelligence.",
               cve);
    finding_set_detail(f, d.data);
    buf_free(&d);

    json_value_t *meta = json_object();
    json_object_set_str(meta, "cve", cve);
    json_object_set(meta, "cisa_kev", json_bool(1));
    json_object_set(meta, "in_the_wild", json_bool(1));
    /* Absent from the EPSS response means "unknown", which Python serialized
     * as null — not as 0.0. */
    json_object_set(meta, "epss_score",
                    epss->present ? json_number(epss->score) : json_null());
    finding_set_meta(f, meta);
    orch_add(ctx, f);
}

static void emit_epss(orchestrator_t *ctx, const char *target,
                      const char *cve, double score)
{
    double pct = score * 100.0;

    buf_t v;
    buf_init(&v);
    buf_printf(&v, "High EPSS Score: %s (%.1f%% probability)", cve, pct);

    finding_t *f = finding_new(TI_TOOL, FT_THREAT_INTEL, v.data, target, SEV_HIGH);
    buf_free(&v);
    if (!f) return;

    buf_t d;
    buf_init(&d);
    buf_printf(&d,
               "PREDICTIVE EXPLOIT THREAT: EPSS model calculates a %.1f%% probability of active "
               "exploitation in the wild within 30 days.", pct);
    finding_set_detail(f, d.data);
    buf_free(&d);

    json_value_t *meta = json_object();
    json_object_set_str(meta, "cve", cve);
    json_object_set_num(meta, "epss_score", score);
    /* Named "percentile" upstream but carries the percentage. Preserved so
     * report output stays byte-comparable with the Python findings. */
    json_object_set_num(meta, "epss_percentile", pct);
    finding_set_meta(f, meta);
    orch_add(ctx, f);
}

static void note_feed(orchestrator_t *ctx, const char *target,
                      const char *value, const char *why)
{
    buf_t d;
    buf_init(&d);
    buf_printf(&d, "Threat intel correlation degraded: %s. "
                   "Findings for the other feed are still reported.", why);
    orch_note(ctx, TI_TOOL, value, target, d.data);
    buf_free(&d);
}

static int run(orchestrator_t *ctx, const char *target)
{
    /* Snapshot the CVE set before emitting anything: orch_add() appends to
     * ctx->findings, the very list being scanned. */
    cve_set_t cves;
    memset(&cves, 0, sizeof(cves));

    for (const finding_t *f = ctx->findings; f; f = f->next) {
        if (f->value) scan_cves(f->value, &cves);
        if (f->detail) scan_cves(f->detail, &cves);
    }

    if (cves.n == 0) { cve_free(&cves); return 0; }   /* Python's early return */

    /* Python: cve_list = sorted(cves). Sorting also makes the EPSS batch
     * deterministic, since only the first 30 CVEs are queried. */
    qsort(cves.v, cves.n, sizeof(*cves.v), cmp_cve);

    const char *kev_why = NULL;
    if (load_kev(&kev_why) != 0)
        note_feed(ctx, target, "threat_intel: CISA KEV catalog unavailable", kev_why);

    size_t n_query = cves.n < TI_EPSS_BATCH ? cves.n : TI_EPSS_BATCH;
    epss_row_t *rows = calloc(n_query, sizeof(*rows));
    if (!rows) {
        cve_free(&cves);
        return 0;
    }
    for (size_t i = 0; i < n_query; i++) {
        snprintf(rows[i].cve, sizeof(rows[i].cve), "%s", cves.v[i]);
        rows[i].present = 0;
        rows[i].score = 0.0;
    }

    const char *epss_why = NULL;
    if (query_epss(cves.v, n_query, rows, &epss_why) != 0)
        note_feed(ctx, target, "threat_intel: FIRST EPSS lookup unavailable", epss_why);

    for (size_t i = 0; i < cves.n; i++) {
        const epss_row_t *row = (i < n_query) ? &rows[i] : NULL;
        if (kev_contains(cves.v[i]))
            emit_kev(ctx, target, cves.v[i], row);
        if (row && row->present && row->score >= TI_EPSS_FLOOR)
            emit_epss(ctx, target, cves.v[i], row->score);
    }

    free(rows);
    cve_free(&cves);
    return 0;
}

const plugin_t threat_intel_plugin = {
    TI_TOOL,
    "Correlate discovered CVEs against CISA KEV (in-the-wild exploitation) and EPSS scoring",
    STAGE_INTEL,
    { NULL },
    run
};
