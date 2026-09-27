/* pkg_audit.c — port of PkgAuditPlugin
 * (sentinel/core/plugins/pkg_audit_plugin.py).
 *
 * Inventories the packages actually installed on this host (dpkg, rpm, and the
 * Python environment) and correlates exact versions against OSV, so the report
 * shows real CVE exposure on the machine rather than a guess from banners.
 *
 * Deliberate divergence: Python shelled out to `dpkg-query`/`rpm` via
 * subprocess. The dpkg database is read directly here — same data, no
 * subprocess, and it still works in slim images that ship the database without
 * dpkg-query. `rpm` has no equivalent on-disk format this cheap to parse, so
 * that fallback still execs the binary, through argv and never a shell string.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/sentinel.h"
#include "sentinel/config.h"   /* bin_path(), bin_available() */
#include "osv_client.h"

#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>

#define PLUGIN_NAME "pkg_audit"
#define OSV_TIMEOUT 10          /* Python urlopen(timeout=10) */
#define DPKG_STATUS_FILE "/var/lib/dpkg/status"
#define PY_PKG_CAP 25           /* Python: _get_python_packages()[:25] */

typedef struct {
    const char *eco;   /* string literal: the source owns it */
    char *name;
    char *ver;
} pkg_t;

typedef struct {
    pkg_t *items;
    size_t count, cap;
} pkg_list_t;

static void pkg_add(pkg_list_t *l, const char *eco, const char *name, const char *ver)
{
    if (!name || !*name || !ver || !*ver) return;
    if (l->count == l->cap) {
        size_t want = l->cap ? l->cap * 2 : 128;
        pkg_t *grown = realloc(l->items, want * sizeof(*grown));
        if (!grown) return;
        l->items = grown;
        l->cap = want;
    }
    char *n = sstrdup(name), *v = sstrdup(ver);
    if (!n || !v) { free(n); free(v); return; }
    l->items[l->count].eco = eco;
    l->items[l->count].name = n;
    l->items[l->count].ver = v;
    l->count++;
}

static void pkg_list_free(pkg_list_t *l)
{
    for (size_t i = 0; i < l->count; i++) {
        free(l->items[i].name);
        free(l->items[i].ver);
    }
    free(l->items);
    l->items = NULL;
    l->count = l->cap = 0;
}

/* "Package: nginx" -> "nginx", bounded, with the leading space skipped. */
static void field_value(const char *line, const char *key, char *out, size_t outlen)
{
    size_t klen = strlen(key);
    if (strncmp(line, key, klen) != 0) return;
    const char *v = line + klen;
    while (*v == ' ' || *v == '\t') v++;
    size_t n = strcspn(v, "\r\n");
    if (n >= outlen) n = outlen - 1;
    memcpy(out, v, n);
    out[n] = '\0';
}

/* Debian/Ubuntu: RFC822-ish stanzas separated by a blank line. Stanzas left
 * behind by a removal ("deinstall ok config-files") are skipped, which is what
 * `dpkg-query -W` reporting only installed packages amounted to. Returns 0 when
 * the file was read, -1 when it is absent. */
static int scan_dpkg_status(pkg_list_t *out)
{
    FILE *fp = fopen(DPKG_STATUS_FILE, "r");
    if (!fp) return -1;

    char line[4096];
    char name[256] = "", ver[256] = "", status[128] = "";
    int installed = 0;

    while (fgets(line, sizeof line, fp)) {
        if (line[0] == '\n' || line[0] == '\r' || line[0] == '\0') {
            if (installed) pkg_add(out, "Debian", name, ver);
            name[0] = ver[0] = status[0] = '\0';
            installed = 0;
            continue;
        }
        if (strncmp(line, "Package:", 8) == 0) {
            field_value(line, "Package:", name, sizeof name);
        } else if (strncmp(line, "Version:", 8) == 0) {
            field_value(line, "Version:", ver, sizeof ver);
        } else if (strncmp(line, "Status:", 7) == 0) {
            field_value(line, "Status:", status, sizeof status);
            installed = strstr(status, " installed") != NULL;
        }
    }
    if (installed) pkg_add(out, "Debian", name, ver);

    fclose(fp);
    return 0;
}

/* RHEL/CentOS/Fedora/Alma. Kept as a subprocess because the rpmdb is a Berkeley
 * DB of index blobs, not a text file worth re-parsing. */
static void scan_rpm(pkg_list_t *out)
{
    if (!bin_available("rpm")) return;

    char *argv[] = { (char *)bin_path("rpm"), "-qa", "--qf",
                     (char *)"%{NAME} %{VERSION}\n", NULL };
    size_t len = 0;
    char *text = proc_capture(argv, &len, 15);
    if (!text) return;

    for (char *line = text; line && *line; ) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        str_trim(line);

        char name[256] = "", ver[256] = "";
        char *sp = strchr(line, ' ');
        if (sp) {
            *sp = '\0';
            snprintf(name, sizeof name, "%s", line);
            snprintf(ver, sizeof ver, "%s", sp + 1);
            str_trim(ver);
            pkg_add(out, "Red Hat", name, ver);
        }
        line = nl ? nl + 1 : NULL;
    }
    free(text);
}

/* Stand-in for Python's importlib.metadata.distributions(): every installed
 * *.dist-info / *.egg-info directory in a site-packages tree carries the same
 * Name/Version pair as the distribution metadata object. */
static void scan_metadata_file(pkg_list_t *out, const char *path)
{
    long size = file_size(path);
    if (size <= 0 || size > 65536) return;   /* 64 KiB is far above a real METADATA */

    size_t len = 0;
    char *text = read_file(path, &len);
    if (!text) return;

    char name[256] = "", ver[256] = "";
    for (size_t off = 0; off < len; ) {
        char *line = text + off;
        char *nl = strchr(line, '\n');
        size_t linelen = nl ? (size_t)(nl - line) : strlen(line);
        char *copy = sstrndup(line, linelen);
        if (!copy) break;
        str_trim(copy);

        if (!copy[0]) { free(copy); break; }   /* headers end at the blank line */
        if (strncmp(copy, "Name:", 5) == 0) field_value(copy, "Name:", name, sizeof name);
        else if (strncmp(copy, "Version:", 8) == 0) field_value(copy, "Version:", ver, sizeof ver);

        free(copy);
        if (!nl) break;
        off += linelen + 1;
    }
    free(text);
    pkg_add(out, "PyPI", name, ver);
}

static void scan_dist_info(pkg_list_t *out, const char *dir, size_t *budget)
{
    DIR *d = opendir(dir);
    if (!d) return;

    struct dirent *e;
    while (*budget > 0 && (e = readdir(d)) != NULL) {
        const char *n = e->d_name;
        size_t len = strlen(n);
        if (n[0] == '.') continue;   /* skip . and .. and the like */

        const char *meta;
        if (len >= 10 && strcmp(n + len - 10, ".dist-info") == 0) meta = "METADATA";
        else if (len >= 9 && strcmp(n + len - 9, ".egg-info") == 0) meta = "PKG-INFO";
        else continue;

        char path[1024];
        snprintf(path, sizeof path, "%s/%s/%s", dir, n, meta);
        size_t before = out->count;
        scan_metadata_file(out, path);
        if (out->count > before) (*budget)--;
    }
    closedir(d);
}

static void scan_lib_dir(pkg_list_t *out, const char *base, size_t *budget)
{
    DIR *d = opendir(base);
    if (!d) return;

    struct dirent *e;
    while (*budget > 0 && (e = readdir(d)) != NULL) {
        const char *n = e->d_name;
        /* Versioned dirs only: python3, python3.12, python3.12t ... */
        if (strncmp(n, "python3", 7) != 0) continue;
        char sub[1024];
        snprintf(sub, sizeof sub, "%s/%s/site-packages", base, n);
        scan_dist_info(out, sub, budget);
        if (*budget == 0) break;
        snprintf(sub, sizeof sub, "%s/%s/dist-packages", base, n);
        scan_dist_info(out, sub, budget);
    }
    closedir(d);
}

static void scan_python_env(pkg_list_t *out)
{
    size_t budget = PY_PKG_CAP;
    const char *bases[] = { "/usr/lib", "/usr/local/lib", "/usr/lib64", NULL };
    const char *home = getenv("HOME");

    for (int i = 0; bases[i] && budget; i++)
        scan_lib_dir(out, bases[i], &budget);
    if (budget && home && *home) {
        char base[1024];
        snprintf(base, sizeof base, "%s/.local/lib", home);
        scan_lib_dir(out, base, &budget);
    }
}

/* Python's priority_keywords: the packages most worth correlating are the
 * web/crypto/network-facing ones, and there are far too many dpkg entries to
 * query individually. */
static int is_priority(const char *name)
{
    static const char *KEYWORDS[] = {
        "ssl", "tls", "ssh", "crypto", "http", "flask", "django", "urllib",
        "requests", "jinja", "tornado", "aiohttp", "fastapi", NULL
    };
    for (int i = 0; KEYWORDS[i]; i++)
        if (str_contains(name, KEYWORDS[i])) return 1;
    return 0;
}

static int is_local_target(const char *target)
{
    static const char *LOCAL[] = { "localhost", "127.0.0.1", "::1", "local", "server", NULL };
    for (int i = 0; LOCAL[i]; i++)
        if (strcmp(target, LOCAL[i]) == 0) return 1;
    return strncmp(target, "127.", 4) == 0;
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

    /* Python's gate: this plugin audits the machine Sentinel runs on, so it
     * stands down for a remote target unless the orchestrator flagged a server
     * audit. Python returned silently here rather than emitting a note. */
    if (!is_local_target(target) && !ctx->server_audit) return 0;

    pkg_list_t pkgs = { NULL, 0, 0 };
    int have_dpkg_db = (scan_dpkg_status(&pkgs) == 0);
    if (pkgs.count == 0) scan_rpm(&pkgs);
    /* Always audit the Python environment too: those are the packages running
     * this agent's own dependencies. */
    scan_python_env(&pkgs);

    if (pkgs.count == 0) {
        orch_note(ctx, PLUGIN_NAME, "no package inventory available", target,
                  have_dpkg_db
                      ? "No installed packages were found: the dpkg database was empty "
                        "or unreadable, rpm was unavailable, and no Python site-packages "
                        "distributions were found. No OS package CVE correlation was performed."
                      : "Package inventory is unavailable: " DPKG_STATUS_FILE " could not "
                        "be read, rpm was unavailable, and no Python site-packages "
                        "distributions were found. No OS package CVE correlation was performed.");
        return 0;
    }

    /* sample = prioritized[:10] if any priority keyword hit, else packages[:5] */
    size_t *order = malloc(pkgs.count * sizeof(*order));
    if (!order) { pkg_list_free(&pkgs); return 0; }

    size_t n_order = 0;
    for (size_t i = 0; i < pkgs.count; i++) {
        char low[256];
        str_lower(pkgs.items[i].name, low, sizeof low);
        if (is_priority(low)) order[n_order++] = i;
    }

    size_t take;
    if (n_order) take = n_order < 10 ? n_order : 10;
    else {
        n_order = pkgs.count < 5 ? pkgs.count : 5;
        for (size_t i = 0; i < n_order; i++) order[i] = i;
        take = n_order;
    }

    /* seen_vulns in Python: one finding per OSV id across all packages. */
    char **seen = NULL;
    size_t seen_count = 0, seen_cap = 0;
    int queried = 0, transport_fail = 0, bad_response = 0;

    for (size_t i = 0; i < take; i++) {
        const pkg_t *p = &pkgs.items[order[i]];

        osv_result_t res = OSV_OK;
        json_value_t *root = osv_query(p->eco, p->name, p->ver, OSV_TIMEOUT, &res);
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

            int dup = 0;
            for (size_t s = 0; s < seen_count; s++)
                if (strcmp(seen[s], vid) == 0) { dup = 1; break; }
            if (dup) continue;
            if (seen_count == seen_cap) {
                size_t want = seen_cap ? seen_cap * 2 : 32;
                char **grown = realloc(seen, want * sizeof(*grown));
                if (!grown) break;
                seen = grown;
                seen_cap = want;
            }
            seen[seen_count] = sstrdup(vid);
            if (!seen[seen_count]) break;
            seen_count++;

            /* Python: (v.get("summary") or v.get("details") or "")[:200] */
            const char *summary = json_get_str(vuln, "summary");
            if (!summary) summary = json_get_str(vuln, "details");
            char *snip = truncate_200(summary ? summary : "");

            char value[512];
            snprintf(value, sizeof value, "%s (%s): %s", p->name, p->ver, vid);

            char detail[1024];
            snprintf(detail, sizeof detail,
                     "Installed package '%s %s' affected by %s: %s",
                     p->name, p->ver, vid, snip);
            free(snip);

            finding_t *f = finding_new(PLUGIN_NAME, FT_VULNERABILITY, value,
                                       target, osv_severity(vuln, SEV_MEDIUM));
            if (f) {
                finding_set_detail(f, detail);

                json_value_t *meta = json_object();
                json_object_set_str(meta, "ecosystem", p->eco);
                json_object_set_str(meta, "package", p->name);
                json_object_set_str(meta, "version", p->ver);
                json_object_set_str(meta, "osv_id", vid);
                /* Python: v.get("aliases", []) — an array, empty when absent. */
                json_value_t *aliases = json_array();
                const json_value_t *al = json_get(vuln, "aliases");
                for (size_t a = 0; a < json_len(al); a++) {
                    const char *alias = json_str_at(al, a);
                    if (alias) json_array_push(aliases, json_string(alias));
                }
                json_object_set(meta, "aliases", aliases);
                finding_set_meta(f, meta);

                orch_add(ctx, f);
            }
        }
        json_free(root);
    }

    /* Python stored every id in ctx.discovered_cves for the threat_intel
     * plugin to enrich with KEV/EPSS; orchestrator_t has no such field, so the
     * hand-off is left to that plugin re-reading the findings. */
    if (!queried && (transport_fail || bad_response)) {
        orch_note(ctx, PLUGIN_NAME, "OSV package correlation unavailable", target,
                  transport_fail
                      ? "api.osv.dev was unreachable, so no installed package was checked "
                        "against known CVEs for this host."
                      : "api.osv.dev returned a response outside the documented vulns[] shape, "
                        "so no installed package was checked against known CVEs for this host.");
    }

    for (size_t s = 0; s < seen_count; s++) free(seen[s]);
    free(seen);
    free(order);
    pkg_list_free(&pkgs);
    return 0;
}

const plugin_t pkg_audit_plugin = {
    PLUGIN_NAME,
    "Audit installed server OS packages and Python environments against OSV for live CVE exposure",
    STAGE_SCAN,
    { NULL },
    run
};
