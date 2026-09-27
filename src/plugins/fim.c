/* fim.c — cryptographic file integrity monitoring and anti-persistence audit.
 *
 * Ported from sentinel/core/plugins/fim_plugin.py (FimPlugin). Three audits
 * that the Python ran from one run(), in this order: baseline comparison of
 * the critical config files, a permissions sweep of the persistence
 * directories, and the kernel taint flag.
 *
 * Latent Python bug fixed here: _audit_file_integrity did
 *     baseline = state_path(FIM_BASELINE_NAME)
 *     ensure_state_dir()
 *     baseline = {}            # clobbers the path
 *     if os.path.exists(baseline):   # os.path.exists({}) raises TypeError
 * and that os.path.exists() call sat *outside* the try/except, so the
 * TypeError escaped run() and the orchestrator recorded "plugin error" on
 * every single invocation. No FIM finding was ever produced by the Python.
 * The port keeps the intent — load the baseline from the state path, compare,
 * merge, and write it back — which is the only reading under which the plugin
 * does its job.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/sentinel.h"

#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define NAME "fim_audit"
#define FIM_BASELINE_NAME "fim_baseline.json"

static const char *CRITICAL_PATHS[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/resolv.conf",
    "/etc/ld.so.conf",
};
#define NCRITICAL (sizeof(CRITICAL_PATHS) / sizeof(CRITICAL_PATHS[0]))

static const char *PERSISTENCE_DIRS[] = {
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/systemd/system",
    "/var/spool/cron/crontabs",
};
#define NPERSIST (sizeof(PERSISTENCE_DIRS) / sizeof(PERSISTENCE_DIRS[0]))

static int is_local_target(const char *t)
{
    return strcmp(t, "localhost") == 0 || strcmp(t, "127.0.0.1") == 0 ||
           strcmp(t, "::1") == 0         || strcmp(t, "local") == 0 ||
           strcmp(t, "server") == 0     || strncmp(t, "127.", 4) == 0;
}

/* A persistence filename is whatever a local user managed to create, and it
 * lands in the HTML report. Escape it. */
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

static void add_finding(orchestrator_t *ctx, const char *target, finding_type_t type,
                        severity_t sev, const char *value, const char *detail,
                        json_value_t *meta)
{
    finding_t *f = finding_new(NAME, type, value, target, sev);
    if (f) {
        finding_set_detail(f, detail);
        finding_set_meta(f, meta);
        orch_add(ctx, f);
    } else {
        json_free(meta);
    }
}

/* FimPlugin._audit_file_integrity */
static void audit_file_integrity(orchestrator_t *ctx, const char *target)
{
    /* The baseline is agent state: it must live in the relocatable state dir,
     * never a hardcoded ~/.sentinel and never the working directory. */
    char *baseline_path = sstrdup(paths_state_path(FIM_BASELINE_NAME));
    if (paths_ensure_dir() != 0) {
        char d[512];
        snprintf(d, sizeof(d),
                 "Could not create the Sentinel state directory; FIM baseline "
                 "integrity comparison skipped.");
        orch_note(ctx, NAME, "FIM baseline unavailable", target, d);
        free(baseline_path);
        return;
    }

    json_value_t *baseline = NULL;
    size_t len = 0;
    char *raw = read_file(baseline_path, &len);
    if (raw) {
        baseline = json_parse(raw, len);
        free(raw);
        if (baseline && baseline->type != JSON_OBJECT) {
            json_free(baseline);
            baseline = NULL;
        }
    }
    if (!baseline) baseline = json_object();

    for (size_t i = 0; i < NCRITICAL; i++) {
        const char *p = CRITICAL_PATHS[i];

        struct stat st;
        if (stat(p, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        char *h = sha256_file_hex(p);
        if (!h) continue;   /* Python: `if h:` — an unreadable file is skipped */

        const json_value_t *prev_node = json_get(baseline, p);
        if (prev_node) {
            const char *prev_h = (prev_node->type == JSON_STRING) ? prev_node->string : NULL;
            /* A non-string baseline entry is itself evidence of tampering with
             * the baseline store, so it reports as a violation rather than
             * being silently coerced. */
            if (!prev_h || strcmp(h, prev_h) != 0) {
                char prev12[16];
                snprintf(prev12, sizeof(prev12), "%.12s", prev_h ? prev_h : "???");

                char value[512];
                snprintf(value, sizeof(value), "FIM Integrity Violation: %s", p);
                char detail[1024];
                snprintf(detail, sizeof(detail),
                         "CRITICAL FILE TAMPERING DETECTED: Cryptographic hash of %s "
                         "changed! Previous: %s... -> Current: %.12s...", p, prev12, h);

                json_value_t *meta = json_object();
                json_object_set_str(meta, "path", p);
                json_object_set_str(meta, "previous_hash", prev_h ? prev_h : "");
                json_object_set_str(meta, "current_hash", h);
                json_object_set_str(meta, "threat_category", "fim_tampering");
                add_finding(ctx, target, FT_VULNERABILITY, SEV_CRITICAL,
                            value, detail, meta);
            }
        }
        /* Python: baseline.update(current_hashes) — adopt whatever is on disk
         * now, so the first run seeds the store and later runs detect drift. */
        json_object_set_str(baseline, p, h);
        free(h);
    }

    char *out = json_dump(baseline, 2);
    if (out) {
        write_file(baseline_path, out, strlen(out));
        free(out);
    }
    json_free(baseline);
    free(baseline_path);
}

/* FimPlugin._audit_persistence */
static void audit_persistence(orchestrator_t *ctx, const char *target)
{
    size_t found = 0;

    for (size_t i = 0; i < NPERSIST; i++) {
        DIR *d = opendir(PERSISTENCE_DIRS[i]);
        if (!d) continue;   /* Python: os.path.isdir guard */

        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;

            char full[1024];
            if (snprintf(full, sizeof(full), "%s/%s", PERSISTENCE_DIRS[i], de->d_name)
                >= (int)sizeof(full))
                continue;   /* Python raised on the join; skipping is the same */

            struct stat st;
            if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) continue;

            unsigned mode = (unsigned)(st.st_mode & 07777);   /* stat.S_IMODE */
            if (mode & 0002u) {
                char perm[16];
                snprintf(perm, sizeof(perm), "0o%03o", mode);   /* Python oct(mode) */

                char *esc = html_escape(full);
                char value[1200];
                snprintf(value, sizeof(value), "World-Writable Persistence Script: %s", esc);
                char detail[1400];
                snprintf(detail, sizeof(detail),
                         "Insecure permissions (%s) on persistence file %s. "
                         "Any local user can escalate to root.", perm, esc);

                json_value_t *meta = json_object();
                json_object_set_str(meta, "path", full);
                json_object_set_str(meta, "permissions", perm);
                add_finding(ctx, target, FT_VULNERABILITY, SEV_CRITICAL,
                            value, detail, meta);
                free(esc);
            }
            /* Python appends to found_cron_scripts for every regular file, not
             * just the world-writable ones. */
            found++;
        }
        closedir(d);
    }

    if (found > 0) {
        char value[96];
        snprintf(value, sizeof(value), "Persistence Monitored (%u units)", (unsigned)found);
        char detail[256];
        snprintf(detail, sizeof(detail),
                 "Audited %u cron and systemd persistence files for integrity and permissions.",
                 (unsigned)found);
        json_value_t *meta = json_object();
        json_object_set_num(meta, "monitored_units", (double)found);
        add_finding(ctx, target, FT_HARDENING, SEV_INFO, value, detail, meta);
    }
}

/* FimPlugin._audit_kernel_taint */
static void audit_kernel_taint(orchestrator_t *ctx, const char *target)
{
    char *val = read_sysctl("/proc/sys/kernel/tainted");
    if (!val) return;

    if (*val && strcmp(val, "0") != 0) {
        char *esc = html_escape(val);
        char value[256];
        snprintf(value, sizeof(value), "Kernel Tainted Flag: %s", esc);
        char detail[512];
        snprintf(detail, sizeof(detail),
                 "KERNEL INTEGRITY COMPROMISE: Kernel taint flag is %s (non-zero). "
                 "Indicates out-of-tree, proprietary, or unauthorized module/rootkit "
                 "was loaded.", esc);

        json_value_t *meta = json_object();
        json_object_set_str(meta, "taint_value", val);
        json_object_set_str(meta, "threat_category", "kernel_taint");
        add_finding(ctx, target, FT_VULNERABILITY, SEV_HIGH, value, detail, meta);
        free(esc);
    }
    free(val);
}

static int run(orchestrator_t *ctx, const char *target)
{
    if (!is_local_target(target) && !ctx->server_audit) return 0;

    /* Python gated the whole engine on sys.platform.startswith("linux"). */
#if defined(__linux__)
    audit_file_integrity(ctx, target);
    audit_persistence(ctx, target);
    audit_kernel_taint(ctx, target);
#else
    const char *platform =
#if defined(__APPLE__)
        "darwin";
#elif defined(_WIN32)
        "win32";
#else
        "unknown";
#endif
    char value[128];
    snprintf(value, sizeof(value), "FIM baseline audit inactive on %s", platform);
    char detail[256];
    snprintf(detail, sizeof(detail),
             "FIM engine active on Linux servers. Platform %s skipped.", platform);
    json_value_t *meta = json_object();
    json_object_set_str(meta, "platform", platform);
    add_finding(ctx, target, FT_HARDENING, SEV_INFO, value, detail, meta);
#endif
    return 0;
}

const plugin_t fim_plugin = {
    "fim_audit",
    "Cryptographic File Integrity Monitoring (FIM) and anti-persistence audit",
    STAGE_AUDIT,
    { NULL },
    run
};
