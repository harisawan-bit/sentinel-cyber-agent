/* osv_correlate.c — port of OsvCorrelatePlugin
 * (sentinel/core/plugins/osv_correlate_plugin.py).
 *
 * Turns technology fingerprints discovered earlier in the run into a
 * prioritised CVE list by asking OSV which packages are vulnerable. The
 * "glue" between recon and reporting: no separate manual step, no local DB.
 */
#include "sentinel/sentinel.h"
#include "osv_client.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define PLUGIN_NAME "osv-correlate"
#define OSV_TIMEOUT 20   /* Python urlopen(timeout=20) */

/* Python PKG_MAP. Entries with an empty ecosystem are inert: the original
 * loop starts with `if not pkg or not pkg[0]: continue`, so nginx, apache,
 * php, openssl, tomcat and redis never reach the API. That is preserved
 * rather than "fixed" — the ternary the original carried for nginx
 * (`("Debian", "nginx") if False else ("", "nginx")`) always evaluated to the
 * empty ecosystem, and OSV rejects an empty ecosystem with HTTP 400, so
 * enabling it would add findings the Python report never produced. */
static const struct {
    const char *token;
    const char *ecosystem;
    const char *package;
} PKG_MAP[] = {
    { "wordpress",  "Packagist", "wordpress/wordpress" },
    { "cloudflare", "",         "" },                    /* infra, not a package */
    { "nginx",      "",         "nginx" },
    { "apache",     "",         "httpd" },
    { "php",        "",         "php" },
    { "openssl",    "",         "openssl" },
    { "jquery",     "npm",      "jquery" },
    { "drupal",     "Packagist", "drupal/drupal" },
    { "spring",     "Maven",    "org.springframework:spring-core" },
    { "tomcat",     "",         "tomcat" },
    { "node.js",    "npm",      "node" },
    { "python",     "PyPI",     "python" },
    { "rails",      "RubyGems", "rails" },
    { "django",     "PyPI",     "django" },
    { "redis",      "",         "redis" },
    { NULL,         NULL,       NULL }
};

/* Python: re.match(r".*=([\w.\-]+)", tk). The leading `.+` is greedy, so this
 * is the run of word/dot/dash characters after the *last* '=' that is itself
 * followed by one — "server=nginx/1.18" yields "nginx", "a=b=c" yields "c". */
static char *tech_token(const char *tk)
{
    if (!tk) return NULL;

    const char *start = NULL;
    for (const char *p = tk; (p = strchr(p, '=')) != NULL; p++) {
        if (p == tk) continue;   /* `.+` requires a character before the '=' */
        unsigned char c = (unsigned char)p[1];
        if (c && (isalnum(c) || c == '.' || c == '-' || c == '_')) start = p + 1;
    }
    if (!start) return NULL;

    size_t n = 0;
    while (start[n]) {
        unsigned char c = (unsigned char)start[n];
        if (!(isalnum(c) || c == '.' || c == '-' || c == '_')) break;
        n++;
    }
    char *tok = malloc(n + 1);
    if (!tok) return NULL;
    for (size_t i = 0; i < n; i++)
        tok[i] = (char)tolower((unsigned char)start[i]);
    tok[n] = '\0';
    return tok;
}

/* Token set. Python used a `set` (which also randomised iteration order); an
 * insertion-ordered list keeps output stable and makes the dedupe explicit. */
typedef struct {
    char **items;
    size_t count, cap;
} token_list_t;

static int tokens_has(const token_list_t *l, const char *s)
{
    for (size_t i = 0; i < l->count; i++)
        if (strcmp(l->items[i], s) == 0) return 1;
    return 0;
}

/* Takes ownership of `tok`, including the free-if-duplicate path. */
static void tokens_add(token_list_t *l, char *tok)
{
    if (!tok || !*tok || tokens_has(l, tok)) { free(tok); return; }
    if (l->count == l->cap) {
        size_t want = l->cap ? l->cap * 2 : 16;
        char **grown = realloc(l->items, want * sizeof(*grown));
        if (!grown) { free(tok); return; }
        l->items = grown;
        l->cap = want;
    }
    l->items[l->count++] = tok;
}

static void tokens_free(token_list_t *l)
{
    for (size_t i = 0; i < l->count; i++) free(l->items[i]);
    free(l->items);
    l->items = NULL;
    l->count = l->cap = 0;
}

static void collect_techs(const orchestrator_t *ctx, token_list_t *out)
{
    /* ctx->shared_techs is the orchestrator's copy of Python's shared["techs"].
     * The orchestrator already lowercases what it stores; normalising again
     * keeps the plugin correct if that ever changes. */
    for (size_t i = 0; i < ctx->tech_count; i++) {
        char low[256];
        str_lower(ctx->shared_techs[i], low, sizeof low);
        tokens_add(out, sstrdup(low));
    }

    /* The original also walks ctx.all_findings for host findings and
     * re-derives the token from metadata["tech"]; ctx->findings is the C
     * equivalent of that list. */
    for (const finding_t *f = ctx->findings; f; f = f->next) {
        if (f->type != FT_HOST) continue;
        const json_value_t *tech = json_get(f->metadata, "tech");
        for (size_t i = 0; i < json_len(tech); i++)
            tokens_add(out, tech_token(json_str_at(tech, i)));
    }
}

/* Python's s[:200]. sstrndup() copies n bytes unconditionally, so the length
 * has to be clamped here or a short summary over-reads the heap. */
static char *truncate_200(const char *s)
{
    size_t n = strlen(s);
    if (n > 200) n = 200;
    return sstrndup(s, n);
}

static int run(orchestrator_t *ctx, const char *target)
{
    if (!ctx || !target) return 0;

    token_list_t techs = { NULL, 0, 0 };
    collect_techs(ctx, &techs);

    /* Python's seen_cve: one finding per OSV id, even when two mapped packages
     * resolve to the same advisory. */
    token_list_t seen = { NULL, 0, 0 };

    int queried = 0, transport_fail = 0, bad_response = 0;

    for (size_t i = 0; i < techs.count; i++) {
        const char *eco = NULL, *pkg = NULL;
        for (int m = 0; PKG_MAP[m].token; m++) {
            if (strcmp(PKG_MAP[m].token, techs.items[i]) == 0) {
                eco = PKG_MAP[m].ecosystem;
                pkg = PKG_MAP[m].package;
                break;
            }
        }
        /* Same gate as Python: an unmapped token, or one with no ecosystem,
         * is skipped without an API call. */
        if (!eco || !*eco || !pkg || !*pkg) continue;

        osv_result_t res = OSV_OK;
        json_value_t *root = osv_query(eco, pkg, NULL, OSV_TIMEOUT, &res);
        if (!root) {
            if (res == OSV_TRANSPORT_FAIL) transport_fail++;
            else bad_response++;
            continue;
        }
        queried++;

        const json_value_t *vulns = json_get(root, "vulns");
        for (size_t v = 0; v < json_len(vulns); v++) {
            const json_value_t *vuln = json_at(vulns, v);
            const char *vid = json_get_str(vuln, "id");
            if (!vid || !*vid) continue;
            if (tokens_has(&seen, vid)) continue;
            tokens_add(&seen, sstrdup(vid));

            char value[512];
            snprintf(value, sizeof value, "%s: %s", pkg, vid);

            finding_t *f = finding_new(PLUGIN_NAME, FT_VULNERABILITY, value,
                                       target, osv_severity(vuln, SEV_INFO));
            if (!f) continue;

            const char *summary = json_get_str(vuln, "summary");
            if (summary) {
                char *detail = truncate_200(summary);
                finding_set_detail(f, detail);
                free(detail);
            }

            json_value_t *meta = json_object();
            json_object_set_str(meta, "ecosystem", eco);
            json_object_set_str(meta, "package", pkg);
            json_object_set_str(meta, "osv_id", vid);
            finding_set_meta(f, meta);

            orch_add(ctx, f);
        }
        json_free(root);
    }

    /* A dead network is a scan limitation worth recording, not a plugin error
     * (rule 4 of the porting contract). Only say something when nothing at all
     * was learned, so a partially successful run stays quiet. */
    if (!queried && (transport_fail || bad_response)) {
        orch_note(ctx, PLUGIN_NAME, "OSV correlation unavailable", target,
                  transport_fail
                      ? "api.osv.dev was unreachable, so no technology was correlated "
                        "against known CVEs for this target."
                      : "api.osv.dev returned a response outside the documented vulns[] "
                        "shape (unsupported ecosystem or API error), so no technology was "
                        "correlated against known CVEs for this target.");
    }

    tokens_free(&seen);
    tokens_free(&techs);
    return 0;
}

const plugin_t osv_correlate_plugin = {
    PLUGIN_NAME,
    "Map discovered tech to known CVEs via OSV (no binary)",
    STAGE_SCAN,
    { NULL },
    run
};
