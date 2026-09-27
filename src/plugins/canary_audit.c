/* canary_audit.c — honeytoken canary integrity and burner-trap audit.
 *
 * Ported from sentinel/core/plugins/canary_audit_plugin.py
 * (CanaryAuditPlugin.run). Two independent checks live here because the Python
 * did both in one generator: the per-canary tamper/read comparison against the
 * recorded baseline, and the replay of the burner sandbox's trap log.
 *
 * The Python module also declared DEFAULT_CANARY_PATHS and never used it, so
 * it is not carried over.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/sentinel.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define NAME "canary_audit"
#define CANARY_MANIFEST_NAME "canaries.json"
#define BURNER_LOG_NAME      "burner_traps.json"

/* Python: b_events[-10:] */
#define BURNER_TAIL 10

static int is_local_target(const char *t)
{
    return strcmp(t, "localhost") == 0 || strcmp(t, "127.0.0.1") == 0 ||
           strcmp(t, "::1") == 0         || strcmp(t, "local") == 0 ||
           strcmp(t, "server") == 0     || strncmp(t, "127.", 4) == 0;
}

/* Canary paths come out of a JSON manifest that an attacker who has already
 * touched the box can rewrite, and the path lands in the HTML report. Escape
 * it. The metadata dict needs no such pass: json_dump() escapes on serialize. */
static char *html_escape(const char *in)
{
    buf_t b;
    buf_init(&b);
    if (!in) return buf_release(&b);
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        switch (*p) {
            case '&':  buf_puts(&b, "&amp;");  break;
            case '<':  buf_puts(&b, "&lt;");   break;
            case '>':  buf_puts(&b, "&gt;");   break;
            case '"':  buf_puts(&b, "&quot;"); break;
            case '\'': buf_puts(&b, "&#x27;"); break;
            default:
                if (*p < 0x20 || *p == 0x7f) {
                    char ref[8];
                    snprintf(ref, sizeof(ref), "&#x%02X;", *p);
                    buf_puts(&b, ref);
                } else {
                    buf_putc(&b, (char)*p);
                }
        }
    }
    return buf_release(&b);
}

/* CanaryAuditPlugin._hash_file. sha256_file_hex returns NULL on the same
 * conditions the Python's open()/read() raised, so the `except: continue`
 * becomes a NULL check here. */
static void check_canary(orchestrator_t *ctx, const char *target, const char *path,
                         const char *base_hash, double base_atime)
{
    struct stat st;
    if (stat(path, &st) != 0) return;

    double curr_atime = (double)st.st_atime;
    char *curr_hash = sha256_file_hex(path);
    if (!curr_hash) return;   /* Python: except Exception: continue */

    /* Python used canary.get("baseline_atime", 0); a missing or non-numeric
     * baseline reads as 0, which is falsy and therefore never trips the read
     * check. json_get_num already yields the fallback for a non-number. */
    char *esc = html_escape(path);
    char value[1024];
    char detail[2048];
    json_value_t *meta = json_object();
    finding_t *f;

    /* The Python's if/elif/else reported exactly one of the three states:
     * a modified hash outranks a read, being the stronger signal. */
    if (base_hash && *base_hash && strcmp(curr_hash, base_hash) != 0) {
        snprintf(value, sizeof(value), "Canary Honeytoken Modified: %s", esc);
        snprintf(detail, sizeof(detail),
                 "CRITICAL 0-DAY BREACH ALERT: Decoy honeytoken file '%s' has been "
                 "tampered with or modified. Definitive evidence of unauthorized "
                 "internal actor access.", esc);
        json_object_set_str(meta, "canary_path", path);
        json_object_set_str(meta, "baseline_hash", base_hash);
        json_object_set_str(meta, "current_hash", curr_hash);
        json_object_set_str(meta, "threat_category", "deception_compromise");
        f = finding_new(NAME, FT_VULNERABILITY, value, target, SEV_CRITICAL);
    } else if (base_atime != 0.0 && curr_atime > (base_atime + 1.0)) {
        snprintf(value, sizeof(value), "Canary Honeytoken Read: %s", esc);
        snprintf(detail, sizeof(detail),
                 "DECEPTION ALERT: Canary decoy file '%s' was read. Unauthorized "
                 "inspection of decoy credentials or sensitive decoy paths.", esc);
        json_object_set_str(meta, "canary_path", path);
        json_object_set_num(meta, "accessed_at", curr_atime);
        json_object_set_str(meta, "threat_category", "canary_read");
        f = finding_new(NAME, FT_VULNERABILITY, value, target, SEV_HIGH);
    } else {
        snprintf(value, sizeof(value), "Canary Honeytoken Armed: %s", esc);
        snprintf(detail, sizeof(detail),
                 "Honeytoken '%s' is pristine and armed. Zero-day tripwire active.", esc);
        json_object_set_str(meta, "canary_path", path);
        json_object_set_str(meta, "status", "armed");
        f = finding_new(NAME, FT_HARDENING, value, target, SEV_INFO);
    }

    if (f) {
        finding_set_detail(f, detail);
        finding_set_meta(f, meta);
        orch_add(ctx, f);
    } else {
        json_free(meta);
    }
    free(esc);
    free(curr_hash);
}

static void audit_burner(orchestrator_t *ctx, const char *target, const json_value_t *events)
{
    size_t n = json_len(events);
    size_t start = (n > BURNER_TAIL) ? n - BURNER_TAIL : 0;

    for (size_t i = start; i < n; i++) {
        const json_value_t *ev = json_at(events, i);
        if (!ev || ev->type != JSON_OBJECT) continue;

        const char *svc = json_get_str(ev, "service");
        if (!svc) svc = "BURNER_SANDBOX";
        const char *rip = json_get_str(ev, "remote_ip");
        if (!rip) rip = "unknown";
        int rport = (int)json_get_num(ev, "remote_port", 0.0);

        char *e_svc = html_escape(svc);
        char *e_rip = html_escape(rip);

        char value[1024];
        snprintf(value, sizeof(value), "Burner Honeypot Tripped: %s by %s:%d",
                 e_svc, e_rip, rport);
        char detail[1024];
        snprintf(detail, sizeof(detail),
                 "Hostile probe diverted to isolated burner sandbox (%s). "
                 "Attacker IP %s trapped.", e_svc, e_rip);

        char ban[768];
        snprintf(ban, sizeof(ban), "iptables -I INPUT -s %s -j DROP", e_rip);

        json_value_t *meta = json_object();
        json_object_set_str(meta, "service", svc);
        json_object_set_str(meta, "attacker_ip", rip);
        json_object_set_num(meta, "remote_port", (double)rport);
        json_object_set_str(meta, "threat_category", "burner_honeypot_diverted");
        json_object_set_str(meta, "iptables_ban", ban);

        finding_t *f = finding_new(NAME, FT_VULNERABILITY, value, target, SEV_CRITICAL);
        if (f) {
            finding_set_detail(f, detail);
            finding_set_meta(f, meta);
            orch_add(ctx, f);
        } else {
            json_free(meta);
        }
        free(e_svc);
        free(e_rip);
    }
}

static void note_unconfigured(orchestrator_t *ctx, const char *target)
{
    finding_t *f = finding_new(NAME, FT_NOTE, "No active honeytokens registered",
                               target, SEV_INFO);
    if (!f) return;
    finding_set_detail(f, "No canary honeytokens found. Register canary decoys "
                           "with Sentinel to detect 0-day intrusions.");
    json_value_t *meta = json_object();
    json_object_set_str(meta, "status", "unconfigured");
    finding_set_meta(f, meta);
    orch_add(ctx, f);
}

static int run(orchestrator_t *ctx, const char *target)
{
    if (!is_local_target(target) && !ctx->server_audit) return 0;

    /* Every state path goes through paths_state_path() and is copied straight
     * away, because the next call invalidates the previous result. Nothing
     * here may assume ~/.sentinel: SENTINEL_HOME relocates it, and it is read
     * fresh on every call. */
    char *manifest_path = sstrdup(paths_state_path(CANARY_MANIFEST_NAME));
    char *burner_path   = sstrdup(paths_state_path(BURNER_LOG_NAME));

    json_value_t *canaries = NULL;
    size_t len = 0;
    char *raw = read_file(manifest_path, &len);
    if (raw) {
        canaries = json_parse(raw, len);
        free(raw);
        if (canaries && canaries->type != JSON_ARRAY) {
            json_free(canaries);
            canaries = NULL;
        }
    }
    size_t ncanaries = json_len(canaries);

    if (ncanaries == 0) {
        /* Python: os.path.abspath(".canary_token") — relative to the process
         * working directory, not the state dir, because that is where
         * --canary-init writes. Preserved verbatim: the read side must agree
         * with the writer. */
        if (file_exists(".canary_token")) {
            struct stat st;
            char *hash = sha256_file_hex(".canary_token");
            if (hash && stat(".canary_token", &st) == 0) {
                /* The synthesized entry baselines the file against its own
                 * current state, so it can only ever report "armed" — which is
                 * what the Python did too. */
                check_canary(ctx, target, ".canary_token", hash, (double)st.st_atime);
                ncanaries = 1;
            }
            free(hash);
        }
    } else {
        for (size_t i = 0; i < ncanaries; i++) {
            const json_value_t *c = json_at(canaries, i);
            if (!c || c->type != JSON_OBJECT) continue;
            const char *path = json_get_str(c, "path");
            if (!path || !*path) continue;
            if (!file_exists(path)) continue;   /* Python: os.path.exists */

            check_canary(ctx, target, path,
                         json_get_str(c, "baseline_hash"),
                         json_get_num(c, "baseline_atime", 0.0));
        }
    }
    json_free(canaries);

    /* The Python's `return` after the unconfigured note short-circuited the
     * burner replay as well, so keep that ordering. */
    if (ncanaries == 0) {
        note_unconfigured(ctx, target);
        free(manifest_path);
        free(burner_path);
        return 0;
    }

    raw = read_file(burner_path, &len);
    if (raw) {
        json_value_t *events = json_parse(raw, len);
        free(raw);
        if (events && events->type == JSON_ARRAY) {
            audit_burner(ctx, target, events);
        } else {
            /* Python's bare `except: pass` would report a corrupt trap log as
             * a quiet sandbox. Note it instead — this covers both a
             * non-array document and json_parse() returning NULL outright. */
            char d[512];
            snprintf(d, sizeof(d),
                     "Burner trap log '%s' is not a readable JSON array; "
                     "recorded sandbox diversions were skipped.", burner_path);
            orch_note(ctx, NAME, "burner trap log unreadable", target, d);
        }
        json_free(events);
    }

    free(manifest_path);
    free(burner_path);
    return 0;
}

const plugin_t canary_audit_plugin = {
    "canary_audit",
    "Audit deception honeytokens and canary files for 0-day post-exploitation detection",
    STAGE_AUDIT,
    { NULL },
    run
};
