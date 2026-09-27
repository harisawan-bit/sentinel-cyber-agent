/* process_anomaly.c — process lineage, LOLBin spawn, and ld.so.preload audit.
 *
 * Ported from sentinel/core/plugins/process_anomaly_plugin.py. This is the
 * plugin that catches post-exploitation the signature engines miss: a web or
 * database daemon spawning a shell, and userland rootkits hiding behind a
 * dynamic-linker preload.
 *
 * Everything here is a /proc read, so there is no external requirement.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/sentinel.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PLUGIN_NAME  "process_anomaly"
#define HOST_TARGET  "localhost"
#define NELEM(a)     (sizeof(a) / sizeof((a)[0]))

/* A daemon that should never be handing out shells. Matched as a *substring*
 * of the parent's comm, which is what makes the forked worker forms
 * ("nginx: worker", "php-fpm: pool") match without enumerating them. */
static const char *SUSPICIOUS_PARENTS[] = {
    "nginx", "apache2", "httpd", "www-data", "caddy", "lighttpd",
    "php-fpm", "gunicorn", "uwsgi", "node", "java", "ruby",
    "mysqld", "mariadbd", "postgres", "mongod", "redis-server"
};

/* LOLBins and shells. Matched as an *exact* comm: these names are specific
 * enough that a substring test would only manufacture false positives. */
static const char *SUSPICIOUS_CHILDREN[] = {
    "sh", "bash", "dash", "zsh", "ksh",
    "curl", "wget", "nc", "netcat", "ncat", "socat",
    "python", "python3", "perl", "ruby", "lua",
    "powershell", "cmd.exe", "whoami", "id"
};

#define CMDLINE_CAP  4096   /* per-process read bound; see cmdline_of() */
#define STAT_CAP     4096
#define MAX_PROCS    65536  /* sanity bound on the process table */
#define MAX_PID_DIGITS 10    /* a pid is an int; anything longer is not one */

typedef struct {
    int   pid;
    int   ppid;
    char  comm[64];
    char *cmdline;   /* malloc'd, NUL-separated argv rendered printable; may be NULL */
} proc_t;

/* ------------------------------------------------------------------ helpers */

/* Same "drop what we cannot render" contract as host_harden.c: the Python read
 * these files with errors="ignore". Escaping is left to report.c / json.c at the
 * serialization boundary, so scrubbing here must not double-escape. */
static char *scrub(char *s)
{
    if (!s) return NULL;
    size_t o = 0;
    for (size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c < 0x7f) {
            s[o++] = (char)c;
        } else if (o > 0 && s[o - 1] != ' ') {
            s[o++] = ' ';
        }
    }
    s[o] = '\0';
    return str_trim(s);
}

/* Read /proc/<pid>/cmdline and render it printable.
 *
 * cmdline is argv as a single NUL-separated blob, not a space-separated line:
 * argv[0] is followed by a NUL, then argv[1], and so on. A raw read therefore
 * has NULs embedded where the eye expects spaces, and strstr() would stop at
 * the first one — matching "bash" would only ever see the program name. The
 * Python did `" ".join(raw.split("\x00")).strip()`, which is exactly "replace
 * every NUL with a space, then trim".
 *
 * Returns NULL when the process is gone or unreadable. Permission denied is
 * routine on a multi-tenant host (other users' processes under hidepid, or
 * simply a different UID) and is never evidence of anything, so it is not
 * reported as an anomaly. */
static char *cmdline_of(int pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    buf_t b; buf_init(&b);
    char chunk[1024];
    size_t n;
    while (b.len < CMDLINE_CAP && (n = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        size_t room = CMDLINE_CAP - b.len;
        buf_append(&b, chunk, n < room ? n : room);
    }
    fclose(f);

    if (!b.data) return NULL;   /* kernel thread: zero-length argv */
    for (size_t i = 0; i < b.len; i++)
        if (b.data[i] == '\0') b.data[i] = ' ';
    return scrub(buf_release(&b));
}

/* Parse /proc/<pid>/stat into `p`. Format: "pid (comm) state ppid ...".
 *
 * comm is attacker-chosen and may itself contain spaces and parentheses, which
 * is why the delimiters are searched rather than split on: the leading '(' is
 * the first one in the file, and the trailing ')' is the last one. Returns 0 on
 * success. */
static int parse_stat(const char *text, proc_t *p)
{
    const char *lparen = strchr(text, '(');
    const char *rparen = strrchr(text, ')');
    if (!lparen || !rparen || rparen < lparen) return -1;

    size_t comm_len = (size_t)(rparen - lparen - 1);
    if (comm_len >= sizeof(p->comm)) comm_len = sizeof(p->comm) - 1;
    memcpy(p->comm, lparen + 1, comm_len);
    p->comm[comm_len] = '\0';
    scrub(p->comm);

    /* Skip ") " then the single-letter state field to reach ppid. */
    const char *q = rparen + 1;
    while (*q == ' ' || *q == '\t') q++;
    while (*q && *q != ' ' && *q != '\t') q++;   /* state */
    while (*q == ' ' || *q == '\t') q++;
    if (!*q) return -1;

    p->ppid = (int)strtol(q, NULL, 10);
    return 0;
}

/* qsort/bsearch key over proc_t by pid — a linear parent lookup would be O(n^2)
 * on a host with thousands of processes. */
static int cmp_pid(const void *a, const void *b)
{
    int pa = ((const proc_t *)a)->pid;
    int pb = ((const proc_t *)b)->pid;
    return (pa > pb) - (pa < pb);
}

static const proc_t *find_pid(const proc_t *ps, size_t n, int pid)
{
    proc_t key;
    key.pid = pid;
    key.ppid = 0;
    key.comm[0] = '\0';
    key.cmdline = NULL;
    return (const proc_t *)bsearch(&key, ps, n, sizeof(proc_t), cmp_pid);
}

/* ---------------------------------------------------------------- the scan */

static proc_t *collect_procs(size_t *out_n)
{
    DIR *d = opendir("/proc");
    if (!d) return NULL;

    proc_t *ps = NULL;
    size_t n = 0;

    struct dirent *de;
    while ((de = readdir(d)) != NULL && n < MAX_PROCS) {
        /* /proc holds far more than PIDs; take only all-digit entries, and cap
         * the length so a hostile name cannot overflow the /proc path buffer. */
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        size_t dlen = strlen(de->d_name);
        if (dlen == 0 || dlen > MAX_PID_DIGITS) continue;
        int ok = 1;
        for (size_t k = 0; k < dlen; k++)
            if (de->d_name[k] < '0' || de->d_name[k] > '9') { ok = 0; break; }
        if (!ok) continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/stat", (int)strtol(de->d_name, NULL, 10));
        size_t slen = 0;
        char *stat = read_file(path, &slen);
        if (!stat) continue;   /* raced with exit, or not ours to read */
        if (slen > STAT_CAP) stat[STAT_CAP] = '\0';

        proc_t p;
        memset(&p, 0, sizeof(p));
        p.pid = (int)strtol(de->d_name, NULL, 10);
        p.ppid = 0;
        int ok_stat = (parse_stat(stat, &p) == 0);
        free(stat);
        if (!ok_stat) continue;

        p.cmdline = cmdline_of(p.pid);
        /* A kernel thread has empty argv; the Python fell back to comm for the
         * display string, which is the only thing we have for it. */
        if (!p.cmdline || !p.cmdline[0]) {
            free(p.cmdline);
            p.cmdline = sstrdup(p.comm);
        }

        proc_t *grown = realloc(ps, (n + 1) * sizeof(proc_t));
        if (!grown) { free(p.cmdline); break; }
        ps = grown;
        ps[n++] = p;
    }
    closedir(d);

    /* Sort by pid so parent lookups can binary search. This also makes the
     * emitted finding order deterministic, where the Python inherited whatever
     * order glob() happened to return. */
    if (ps) qsort(ps, n, sizeof(proc_t), cmp_pid);
    *out_n = n;
    return ps;
}

static void free_procs(proc_t *ps, size_t n)
{
    for (size_t i = 0; i < n; i++) free(ps[i].cmdline);
    free(ps);
}

/* --------------------------------------------------------------- detectors */

static int is_suspicious_parent(const char *comm)
{
    for (size_t i = 0; i < NELEM(SUSPICIOUS_PARENTS); i++)
        if (str_contains(comm, SUSPICIOUS_PARENTS[i])) return 1;
    return 0;
}

static int is_suspicious_child(const char *comm)
{
    for (size_t i = 0; i < NELEM(SUSPICIOUS_CHILDREN); i++)
        if (strcmp(comm, SUSPICIOUS_CHILDREN[i]) == 0) return 1;
    return 0;
}

static void audit_lineage(orchestrator_t *ctx, const proc_t *ps, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        /* ppid 0 (kernel) and 1 (already reaped) have no entry here, and the
         * Python's `if ppid in procs` guard fell through the same way. */
        if (ps[i].ppid <= 0) continue;
        const proc_t *parent = find_pid(ps, n, ps[i].ppid);
        if (!parent) continue;

        char child_comm[64], parent_comm[64];
        str_lower(ps[i].comm, child_comm, sizeof(child_comm));
        str_lower(parent->comm, parent_comm, sizeof(parent_comm));

        if (!is_suspicious_parent(parent_comm)) continue;
        if (!is_suspicious_child(child_comm)) continue;

        const char *cmd = ps[i].cmdline ? ps[i].cmdline : child_comm;

        buf_t v, d; buf_init(&v); buf_init(&d);
        buf_printf(&v, "Suspicious Process Spawn: %s (pid %d) -> %s (pid %d)",
                   parent_comm, parent->pid, child_comm, ps[i].pid);
        buf_printf(&d, "CRITICAL 0-DAY RCE INDICATOR: Server daemon '%s' spawned shell "
                       "or LOLBin '%s'. Command: %.200s", parent_comm, child_comm, cmd);

        json_value_t *m = json_object();
        if (m) {
            json_object_set_num(m, "parent_pid", (double)parent->pid);
            json_object_set_str(m, "parent_comm", parent_comm);
            json_object_set_num(m, "child_pid", (double)ps[i].pid);
            json_object_set_str(m, "child_comm", child_comm);
            json_object_set_str(m, "cmdline", cmd);
            json_object_set_str(m, "threat_category", "0day_rce_execution");
        }

        finding_t *f = finding_new(PLUGIN_NAME, FT_ANOMALY, v.data, HOST_TARGET, SEV_CRITICAL);
        if (f) {
            finding_set_detail(f, d.data);
            if (m) finding_set_meta(f, m); else json_free(m);
            orch_add(ctx, f);
        } else {
            json_free(m);
        }
        buf_free(&v); buf_free(&d);
    }
}

/* A non-empty /etc/ld.so.preload injects a shared object into every dynamically
 * linked process on the host, including setuid binaries. There is no benign
 * reason for one to be present on a server. */
static void audit_rootkit_preload(orchestrator_t *ctx)
{
    if (!file_exists("/etc/ld.so.preload")) return;

    size_t len = 0;
    char *content = scrub(read_file("/etc/ld.so.preload", &len));
    if (!content) return;      /* exists but unreadable: stay quiet, assert nothing */
    if (!*content) { free(content); return; }

    buf_t d; buf_init(&d);
    buf_printf(&d, "POTENTIAL USERLAND ROOTKIT: /etc/ld.so.preload contains injected "
                   "libraries: %.150s", content);

    json_value_t *m = json_object();
    if (m) {
        json_object_set_str(m, "path", "/etc/ld.so.preload");
        json_object_set_str(m, "content", content);
    }
    finding_t *f = finding_new(PLUGIN_NAME, FT_ANOMALY,
                               "Active /etc/ld.so.preload detected", HOST_TARGET,
                               SEV_CRITICAL);
    if (f) {
        finding_set_detail(f, d.data);
        if (m) finding_set_meta(f, m); else json_free(m);
        orch_add(ctx, f);
    } else {
        json_free(m);
    }
    buf_free(&d);
    free(content);
}

/* ----------------------------------------------------------------- the audit */

#if !defined(__linux__)
static const char *PLATFORM_NAME = "posix";
#endif

/* This plugin audits the machine it executes on, so a remote target means
 * "skip" unless the caller flagged a server audit. Preserved from the
 * Python run() guard, which host_harden.c mirrors. */
static int audit_applies(const orchestrator_t *ctx, const char *target)
{
    static const char *LOCAL[] = { "localhost", "127.0.0.1", "::1", "local", "server" };
    for (size_t i = 0; i < NELEM(LOCAL); i++)
        if (strcmp(target, LOCAL[i]) == 0) return 1;
    if (strncmp(target, "127.", 4) == 0) return 1;
    return ctx && ctx->server_audit;
}

static int run(orchestrator_t *ctx, const char *target)
{
    if (!ctx || !target) return 0;
    if (!audit_applies(ctx, target)) return 0;

#if defined(__linux__)
    size_t n = 0;
    proc_t *ps = collect_procs(&n);
    if (!ps) {
        /* /proc is the whole input here; without it there is nothing to scan
         * and nothing to say. Degrade to a note rather than a silent pass. */
        orch_note(ctx, PLUGIN_NAME, "process anomaly audit skipped", HOST_TARGET,
                  "Could not open /proc to enumerate processes. Process lineage "
                  "inspection requires a mounted procfs.");
        return 0;
    }
    audit_lineage(ctx, ps, n);
    audit_rootkit_preload(ctx);
    free_procs(ps, n);
#else
    buf_t v, d; buf_init(&v); buf_init(&d);
    buf_printf(&v, "Process anomaly audit inactive on %s (requires Linux /proc)", PLATFORM_NAME);
    buf_puts(&d, "Process lineage and /proc/stat inspection is active when executed "
                 "on Linux server targets.");
    json_value_t *m = json_object();
    if (m) json_object_set_str(m, "platform", PLATFORM_NAME);
    finding_t *f = finding_new(PLUGIN_NAME, FT_NOTE, v.data, HOST_TARGET, SEV_INFO);
    if (f) {
        finding_set_detail(f, d.data);
        if (m) finding_set_meta(f, m); else json_free(m);
        orch_add(ctx, f);
    } else {
        json_free(m);
    }
    buf_free(&v); buf_free(&d);
#endif
    return 0;
}

const plugin_t process_anomaly_plugin = {
    PLUGIN_NAME,
    "Audit process lineage, reverse shell egress, and rootkit preloads for 0-day detection",
    STAGE_AUDIT,
    { NULL },
    run
};
