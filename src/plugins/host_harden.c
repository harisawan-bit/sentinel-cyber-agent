/* host_harden.c — Linux/host exploit-mitigation and server-hardening auditor.
 *
 * Ported from sentinel/core/plugins/host_harden_plugin.py. The audit half is
 * pure /proc and /etc reads, so the plugin declares no external requirements
 * and never shells out.
 *
 * The --fix-kernel equivalent lives in host_harden_apply_fixes() at the bottom:
 * it writes the /proc/sys values directly (never a shell string) and refuses to
 * act unless the process is already root.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/sentinel.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PLUGIN_NAME  "host_harden"
#define HOST_TARGET  "localhost"
#define NELEM(a)     (sizeof(a) / sizeof((a)[0]))

/* Applied by host_harden_apply_fixes(); mirrors HARDENING_PARAMS in
 * sentinel/core/remediation.py, including the description text that ends up in
 * the generated sysctl profile. */
#define SYSCTL_CONF_PATH "/etc/sysctl.d/99-sentinel-hardening.conf"

typedef struct {
    const char *key;       /* dotted sysctl name, as written into the profile */
    const char *target;    /* value to enforce */
    const char *proc_path; /* live knob under /proc/sys */
    const char *desc;      /* human-readable impact, mirrored from the Python */
} fix_param_t;

#if defined(__linux__)
static const fix_param_t FIX_PARAMS[] = {
    { "kernel.randomize_va_space", "2", "/proc/sys/kernel/randomize_va_space",
      "Full ASLR (Heap/Stack/VDSO randomization)" },
    { "kernel.unprivileged_userns_clone", "0", "/proc/sys/kernel/unprivileged_userns_clone",
      "Disables unprivileged user namespaces (neutralizes ~60% of LPE 0-days)" },
    { "kernel.kptr_restrict", "2", "/proc/sys/kernel/kptr_restrict",
      "Hides kernel pointers from unprivileged users" },
    { "kernel.dmesg_restrict", "1", "/proc/sys/kernel/dmesg_restrict",
      "Restricts unprivileged dmesg kernel log access" },
    { "kernel.unprivileged_bpf_disabled", "1", "/proc/sys/kernel/unprivileged_bpf_disabled",
      "Disables unprivileged eBPF byte-code loading" },
    { "kernel.yama.ptrace_scope", "1", "/proc/sys/kernel/yama/ptrace_scope",
      "Yama ptrace protection against cross-process memory injection" },
    { "fs.protected_symlinks", "1", "/proc/sys/fs/protected_symlinks",
      "Prevents TOCTOU symlink race conditions" },
    { "fs.protected_hardlinks", "1", "/proc/sys/fs/protected_hardlinks",
      "Prevents unauthorized hardlink hijacking" },
    { "fs.protected_fifos", "2", "/proc/sys/fs/protected_fifos",
      "Restricts FIFO creations in shared world-writable directories" },
    { "fs.protected_regular", "2", "/proc/sys/fs/protected_regular",
      "Prevents writes to regular files in sticky directories" },
    { "net.ipv4.conf.all.rp_filter", "1", "/proc/sys/net/ipv4/conf/all/rp_filter",
      "Reverse-path filtering (anti-spoofing)" },
    { "net.ipv4.conf.all.accept_redirects", "0", "/proc/sys/net/ipv4/conf/all/accept_redirects",
      "Disables ICMP redirects (prevents MITM routing)" },
    { "net.ipv4.icmp_echo_ignore_broadcasts", "1", "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts",
      "Ignores broadcast ICMP echoes (smurf attack prevention)" }
};
#endif

/* CapEff bitmasks that mean "every capability the kernel knows about". */
#if defined(__linux__)
static const char *PRIVILEGED_CAPEFF[] = {
    "0000003fffffffff", "000001ffffffffff"
};
#endif

/* ------------------------------------------------------------------ helpers */

/* Scrub a NUL-terminated string in place to printable ASCII, collapsing runs
 * of unprintables and whitespace into single spaces.
 *
 * The Python opened every one of these files with errors="ignore", which
 * silently dropped bytes it could not decode. A C read has no such filter, so
 * raw bytes would otherwise reach the report; this reproduces the "drop what we
 * cannot render" behaviour. HTML/JSON escaping is NOT done here — report.c and
 * json.c escape at the serialization boundary, and escaping twice would show
 * literal &amp; in the rendered page. */
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

#if defined(__linux__)
/* Sysctl and procfs helper: Linux only. */
/* "key = value" — the shape every sysctl finding value takes in the Python. */
static char *kv(const char *key, const char *val)
{
    buf_t b; buf_init(&b);
    buf_printf(&b, "%s = %s", key, val);
    return buf_release(&b);
}
#endif


/* Walk a NUL-terminated blob one line at a time, destructively. Returns NULL
 * at the end of the buffer. */
static char *next_line(char **cursor)
{
    char *p = *cursor;
    if (!p || !*p) return NULL;
    char *nl = strchr(p, '\n');
    if (nl) { *nl = '\0'; *cursor = nl + 1; }
    else    { *cursor = p + strlen(p); }
    size_t n = strlen(p);
    if (n && p[n - 1] == '\r') p[n - 1] = '\0';
    return p;
}

/* Split `line` on ASCII whitespace into at most `max` tokens, in place. */
static int split_ws(char *line, char **out, int max)
{
    int n = 0;
    char *p = line;
    while (*p && n < max) {
        while (*p == ' ' || *p == '\t' || *p == '\r') p++;
        if (!*p) break;
        out[n++] = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\r') p++;
        if (*p) *p++ = '\0';
    }
    return n;
}

#if defined(__linux__)
/* Sysctl and procfs helper: Linux only. */
/* Exact membership test against a comma-separated mount option string. A
 * substring test would be wrong: "nodev" contains "dev", "nosuid" is a prefix
 * of nothing, but the general case is unsafe. */
static int has_mount_opt(const char *opts, const char *want)
{
    size_t wl = strlen(want);
    const char *p = opts;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (len == wl && strncmp(p, want, wl) == 0) return 1;
        if (!comma) break;
        p = comma + 1;
    }
    return 0;
}
#endif


static void emit(orchestrator_t *ctx, finding_type_t type, severity_t sev,
                 const char *value, const char *detail, json_value_t *meta)
{
    finding_t *f = finding_new(PLUGIN_NAME, type, value, HOST_TARGET, sev);
    if (!f) { json_free(meta); return; }
    finding_set_detail(f, detail);
    if (meta) finding_set_meta(f, meta);
    orch_add(ctx, f);
}

#if defined(__linux__)
/* Sysctl and procfs helper: Linux only. */
/* The mitigation/status metadata shape the Python repeated on every sysctl
 * finding. report.c keys its "Kernel Mitigation" category off "mitigation". */
static void emit_mitigation(orchestrator_t *ctx, severity_t sev,
                            const char *value, const char *detail,
                            const char *mitigation, const char *current,
                            const char *status)
{
    json_value_t *m = json_object();
    if (m) {
        json_object_set_str(m, "mitigation", mitigation);
        json_object_set_str(m, "value", current);
        json_object_set_str(m, "status", status);
    }
    emit(ctx, FT_HARDENING, sev, value, detail, m);
}
#endif


#if defined(__linux__)
/* Sysctl and procfs helper: Linux only. */
/* ------------------------------------------------------------ kernel sysctls */

/* Read one /proc/sys knob. A knob that will not open is appended to `unread`
 * and reported as NULL.
 *
 * The Python's _read_sysctl returned None and the caller silently continued.
 * That is right about the severity (an unreadable knob is a permissions or
 * kernel-capability artifact, never a security issue) but silent, and the
 * parent brief asks for an informational note. Rather than one note per knob —
 * a stock Ubuntu host lacks half of them — the paths are collected and
 * summarized once at the end of the audit. */
static char *read_knob(buf_t *unread, const char *path)
{
    char *v = read_sysctl(path);
    if (!v) {
        buf_puts(unread, path);
        buf_putc(unread, ' ');
        return NULL;
    }
    return scrub(v);
}
#endif


#if defined(__linux__)
/* Reads sysctls, /proc/mounts, and the Docker socket: Linux only. */
static void audit_kernel(orchestrator_t *ctx)
{
    buf_t unread;
    buf_init(&unread);

    /* 1. ASLR — predictable addresses are what turn a memory-corruption bug
     *    into reliable shellcode. */
    char *v = read_knob(&unread, "/proc/sys/kernel/randomize_va_space");
    if (v) {
        if (strcmp(v, "2") == 0) {
            emit_mitigation(ctx, SEV_INFO, "kernel.randomize_va_space = 2",
                "Full ASLR enabled (Heap, Stack, VDSO, and mmap randomization active).",
                "ASLR", v, "secure");
        } else {
            char *value = kv("kernel.randomize_va_space", v);
            emit_mitigation(ctx, strcmp(v, "0") == 0 ? SEV_CRITICAL : SEV_HIGH, value,
                "ASLR is disabled or incomplete! Memory corruption 0-days can execute reliable ROP/shellcode.",
                "ASLR", v, "vulnerable");
            free(value);
        }
        free(v);
    }

    /* 2. Unprivileged user namespaces — the entry point for a large share of
     *    modern container/LPE kernel bugs. */
    v = read_knob(&unread, "/proc/sys/kernel/unprivileged_userns_clone");
    if (v) {
        if (strcmp(v, "0") == 0) {
            emit_mitigation(ctx, SEV_INFO, "kernel.unprivileged_userns_clone = 0",
                "Unprivileged user namespaces disabled. Blocks user namespace privilege escalation chains.",
                "userns", v, "secure");
        } else if (strcmp(v, "1") == 0) {
            emit_mitigation(ctx, SEV_HIGH, "kernel.unprivileged_userns_clone = 1",
                "Unprivileged user namespaces are enabled. Attackers can reach unhardened kernel attack surfaces.",
                "userns", v, "exposed");
        }
        /* Any other value: the Python yielded nothing, and neither do we. */
        free(v);
    }

    /* 3. Kernel pointer restrict — hides kallsyms addresses from userspace. */
    v = read_knob(&unread, "/proc/sys/kernel/kptr_restrict");
    if (v) {
        if (strcmp(v, "1") == 0 || strcmp(v, "2") == 0) {
            char *value = kv("kernel.kptr_restrict", v);
            emit_mitigation(ctx, SEV_INFO, value,
                "Kernel symbol pointers hidden from unprivileged users (/proc/kallsyms).",
                "kptr_restrict", v, "secure");
            free(value);
        } else {
            char *value = kv("kernel.kptr_restrict", v);
            emit_mitigation(ctx, SEV_MEDIUM, value,
                "Kernel addresses exposed via kallsyms. Facilitates kernel exploit offset calculations.",
                "kptr_restrict", v, "vulnerable");
            free(value);
        }
        free(v);
    }

    /* 4. dmesg restriction — kernel logs carry pointers and crash context. */
    v = read_knob(&unread, "/proc/sys/kernel/dmesg_restrict");
    if (v) {
        if (strcmp(v, "1") == 0) {
            emit_mitigation(ctx, SEV_INFO, "kernel.dmesg_restrict = 1",
                "Unprivileged dmesg logging access restricted. Protects kernel crash dumps and pointers.",
                "dmesg_restrict", v, "secure");
        } else {
            /* The Python hardcoded "= 0" in the finding value while putting the
             * real reading in metadata; using the actual value keeps the two
             * consistent and is identical on every kernel that only has 0/1. */
            char *value = kv("kernel.dmesg_restrict", v);
            emit_mitigation(ctx, SEV_LOW, value,
                "Kernel dmesg log buffer accessible to unprivileged users. May leak sensitive addresses.",
                "dmesg_restrict", v, "exposed");
            free(value);
        }
        free(v);
    }

    /* 5. Filesystem TOCTOU protections for world-writable sticky directories.
     *    A "2" setting is strict; "1" is the older weaker mode and still counts
     *    as protected, exactly as the Python decided. */
    {
        static const struct { const char *name, *expected; } fs_params[] = {
            { "protected_symlinks", "1" },
            { "protected_hardlinks", "1" },
            { "protected_fifos",    "2" },
            { "protected_regular",  "2" }
        };
        for (size_t i = 0; i < NELEM(fs_params); i++) {
            char path[128];
            snprintf(path, sizeof(path), "/proc/sys/fs/%s", fs_params[i].name);
            char *val = read_knob(&unread, path);
            if (!val) continue;

            /* The Python's value string carries the "fs." prefix, while its
             * metadata "mitigation" key is the bare knob name. */
            buf_t kv_, detail_key;
            buf_init(&kv_); buf_init(&detail_key);
            buf_printf(&kv_, "fs.%s", fs_params[i].name);
            buf_printf(&detail_key, "fs.%s = %s", fs_params[i].name, val);

            int secure = (strcmp(val, fs_params[i].expected) == 0) ||
                         (strcmp(fs_params[i].expected, "2") == 0 && strcmp(val, "1") == 0);
            if (secure) {
                buf_t d; buf_init(&d);
                buf_printf(&d, "Filesystem TOCTOU symlink/hardlink protection active (%s).",
                           fs_params[i].name);
                emit_mitigation(ctx, SEV_INFO, detail_key.data, d.data,
                                kv_.data, val, "secure");
                buf_free(&d);
            } else {
                buf_t d; buf_init(&d);
                buf_printf(&d, "Filesystem race condition protection disabled (fs.%s). "
                               "Vulnerable to /tmp symlink attacks.", fs_params[i].name);
                emit_mitigation(ctx, SEV_MEDIUM, detail_key.data, d.data,
                                kv_.data, val, "vulnerable");
                buf_free(&d);
            }
            buf_free(&kv_);
            buf_free(&detail_key);
            free(val);
        }
    }

    /* 6. Unprivileged eBPF — bytecode loads straight into the kernel. */
    v = read_knob(&unread, "/proc/sys/kernel/unprivileged_bpf_disabled");
    if (v) {
        if (strcmp(v, "1") == 0 || strcmp(v, "2") == 0) {
            char *value = kv("kernel.unprivileged_bpf_disabled", v);
            emit_mitigation(ctx, SEV_INFO, value,
                "Unprivileged eBPF execution is disabled. Mitigates Spectre and eBPF kernel vulnerabilities.",
                "bpf_restrict", v, "secure");
            free(value);
        } else {
            char *value = kv("kernel.unprivileged_bpf_disabled", v);
            emit_mitigation(ctx, SEV_HIGH, value,
                "Unprivileged eBPF is enabled. Allows arbitrary unprivileged users to load BPF bytecode.",
                "bpf_restrict", v, "exposed");
            free(value);
        }
        free(v);
    }

    /* 7. Yama ptrace_scope — blocks cross-process memory attachment. */
    v = read_knob(&unread, "/proc/sys/kernel/yama/ptrace_scope");
    if (v) {
        int secure = (strcmp(v, "1") == 0 || strcmp(v, "2") == 0 || strcmp(v, "3") == 0);
        if (secure) {
            char *value = kv("kernel.yama.ptrace_scope", v);
            emit_mitigation(ctx, SEV_INFO, value,
                "Yama ptrace protection active. Restricts process memory attachment and injection.",
                "yama", v, "secure");
            free(value);
        } else {
            /* Same "= 0" hardcode as dmesg_restrict above; real value used. */
            char *value = kv("kernel.yama.ptrace_scope", v);
            emit_mitigation(ctx, SEV_MEDIUM, value,
                "Yama ptrace protection disabled. Processes can attach to other processes owned by the same user.",
                "yama", v, "exposed");
            free(value);
        }
        free(v);
    }

    if (unread.len) {
        str_trim(unread.data);
        buf_t d; buf_init(&d);
        buf_printf(&d, "Could not read the following kernel parameters (absent on this "
                       "kernel, or not readable by the current user): %s. They were "
                       "skipped, not treated as findings — an unreadable sysctl is a "
                       "permissions artifact, not a security posture.", unread.data);
        orch_note(ctx, PLUGIN_NAME, "kernel sysctls unreadable", HOST_TARGET, d.data);
        buf_free(&d);
    }
    buf_free(&unread);
}
#endif


#if defined(__linux__)
/* Reads sysctls, /proc/mounts, and the Docker socket: Linux only. */
/* ------------------------------------------------------------ shared mounts */

/* A world-writable mount without noexec/nosuid/nodev is the standard staging
 * ground for a payload drop. */
static void audit_mounts(orchestrator_t *ctx)
{
    static const char *CRITICAL[] = { "/tmp", "/var/tmp", "/dev/shm" };

    if (!file_exists("/proc/mounts")) return;

    size_t len = 0;
    char *text = read_file("/proc/mounts", &len);
    if (!text) return;   /* unreadable /proc: nothing to assert, stay quiet */

    /* Preserve first-seen order like the Python dict did, and let a later
     * duplicate mount line overwrite the options of the entry already seen. */
    char *points[3] = { NULL, NULL, NULL };
    char *opts[3]   = { NULL, NULL, NULL };
    size_t nfound   = 0;

    char *cur = text;
    char *line;
    while ((line = next_line(&cur)) != NULL) {
        char *fields[4];
        if (split_ws(line, fields, 4) < 4) continue;
        for (int i = 0; i < 3; i++) {
            if (strcmp(fields[1], CRITICAL[i]) != 0) continue;
            size_t slot = NELEM(CRITICAL);
            for (size_t s = 0; s < nfound; s++)
                if (strcmp(points[s], CRITICAL[i]) == 0) { slot = s; break; }
            if (slot == NELEM(CRITICAL)) {
                if (nfound >= NELEM(CRITICAL)) break;
                points[nfound] = sstrdup(CRITICAL[i]);
                opts[nfound]   = NULL;
                nfound++;
                slot = nfound - 1;
            }
            free(opts[slot]);
            opts[slot] = sstrdup(fields[3]);
            break;
        }
    }
    free(text);

    for (size_t s = 0; s < nfound; s++) {
        static const char *REQUIRED[] = { "noexec", "nosuid", "nodev" };
        buf_t missing; buf_init(&missing);
        for (size_t r = 0; r < NELEM(REQUIRED); r++)
            if (!has_mount_opt(opts[s], REQUIRED[r]))
                buf_printf(&missing, "%s%s", missing.len ? "," : "", REQUIRED[r]);

        if (missing.len) {
            buf_t v, d; buf_init(&v); buf_init(&d);
            buf_printf(&v, "mount %s: missing %s", points[s], missing.data);
            buf_printf(&d, "Shared temporary path %s allows binary execution or suid elevation.",
                       points[s]);
            json_value_t *m = json_object();
            if (m) {
                json_object_set_str(m, "mount", points[s]);
                json_value_t *arr = json_array();
                char *tok = missing.data;
                while (tok && *tok) {
                    char *comma = strchr(tok, ',');
                    if (comma) *comma = '\0';
                    json_array_push(arr, json_string(tok));
                    tok = comma ? comma + 1 : NULL;
                }
                json_object_set(m, "missing_options", arr);
            }
            emit(ctx, FT_HARDENING, SEV_MEDIUM, v.data, d.data, m);
            buf_free(&v); buf_free(&d);
        } else {
            buf_t v, d; buf_init(&v); buf_init(&d);
            buf_printf(&v, "mount %s: hardened (noexec, nosuid, nodev)", points[s]);
            buf_printf(&d, "%s is protected against binary drop and execution.", points[s]);
            json_value_t *m = json_object();
            if (m) {
                json_object_set_str(m, "mount", points[s]);
                json_object_set_str(m, "status", "secure");
            }
            emit(ctx, FT_HARDENING, SEV_INFO, v.data, d.data, m);
            buf_free(&v); buf_free(&d);
        }
        buf_free(&missing);
        free(points[s]);
        free(opts[s]);
    }
}
#endif


#if defined(__linux__)
/* Reads sysctls, /proc/mounts, and the Docker socket: Linux only. */
/* ----------------------------------------------------- container escape risk */

static void audit_container(orchestrator_t *ctx)
{
    /* A world-accessible Docker socket is root-equivalent: any local user can
     * start a privileged container and mount the host filesystem. */
    if (file_exists("/var/run/docker.sock")) {
        struct stat st;
        if (stat("/var/run/docker.sock", &st) == 0) {
            unsigned mode = (unsigned)(st.st_mode & 07777);
            if (mode & 007) {
                char perms[16];
                snprintf(perms, sizeof(perms), "0%o", mode);
                json_value_t *m = json_object();
                if (m) {
                    json_object_set_str(m, "path", "/var/run/docker.sock");
                    json_object_set_str(m, "permissions", perms);
                }
                emit(ctx, FT_HARDENING, SEV_CRITICAL,
                     "Insecure /var/run/docker.sock permissions",
                     "Docker socket is world-accessible. Any local user can escape to root privileges instantly.",
                     m);
            }
        }
    }

    /* Inside a container with the full capability set, a breakout is trivial. */
    if (file_exists("/proc/1/status") && file_exists("/.dockerenv")) {
        size_t len = 0;
        char *text = read_file("/proc/1/status", &len);
        if (!text) return;
        char *cur = text, *line;
        while ((line = next_line(&cur)) != NULL) {
            if (strncmp(line, "CapEff:", 7) != 0) continue;
            char *capeff = scrub(line + 7);
            if (!capeff || !*capeff) continue;
            for (size_t i = 0; i < NELEM(PRIVILEGED_CAPEFF); i++) {
                if (strcmp(capeff, PRIVILEGED_CAPEFF[i]) != 0) continue;
                json_value_t *m = json_object();
                if (m) json_object_set_str(m, "capeff", capeff);
                emit(ctx, FT_HARDENING, SEV_CRITICAL,
                     "Container running in --privileged mode",
                     "Container has all host capabilities. Breakout to host is trivial.", m);
                break;
            }
        }
        free(text);
    }
}
#endif


/* ------------------------------------------------------------- sshd posture */

static void audit_sshd(orchestrator_t *ctx)
{
    static const char *SSHD_PATHS[] = { "/etc/ssh/sshd_config", "/etc/sshd_config" };

    for (size_t i = 0; i < NELEM(SSHD_PATHS); i++) {
        struct stat st;
        if (stat(SSHD_PATHS[i], &st) != 0 || !S_ISREG(st.st_mode)) continue;

        size_t len = 0;
        char *text = read_file(SSHD_PATHS[i], &len);
        if (!text) continue;

        char *cur = text, *line;
        while ((line = next_line(&cur)) != NULL) {
            char *clean = scrub(line);
            if (!clean || !*clean || clean[0] == '#') continue;

            char *parts[2];
            if (split_ws(clean, parts, 2) < 2) continue;
            char k[64], v[64];
            str_lower(parts[0], k, sizeof(k));
            str_lower(parts[1], v, sizeof(v));

            /* Matches the Python's directive-shape check: it only ever looked
             * at the first two whitespace-separated tokens, and emitted one
             * finding per matching line rather than per file. */
            if (strcmp(k, "permitrootlogin") == 0 &&
                (strcmp(v, "yes") == 0 || strcmp(v, "prohibit-password") == 0)) {
                buf_t val, d; buf_init(&val); buf_init(&d);
                buf_printf(&val, "sshd: PermitRootLogin %s", v);
                buf_printf(&d, "SSH daemon allows root login directly (%s).", v);
                json_value_t *m = json_object();
                if (m) {
                    json_object_set_str(m, "setting", k);
                    json_object_set_str(m, "value", v);
                }
                emit(ctx, FT_HARDENING,
                     strcmp(v, "yes") == 0 ? SEV_HIGH : SEV_LOW,
                     val.data, d.data, m);
                buf_free(&val); buf_free(&d);
            } else if (strcmp(k, "passwordauthentication") == 0 && strcmp(v, "yes") == 0) {
                json_value_t *m = json_object();
                if (m) {
                    json_object_set_str(m, "setting", k);
                    json_object_set_str(m, "value", v);
                }
                emit(ctx, FT_HARDENING, SEV_MEDIUM,
                     "sshd: PasswordAuthentication yes",
                     "Password authentication enabled. Vulnerable to credential stuffing / brute-force.",
                     m);
            }
        }
        free(text);
    }
}

#if defined(__linux__)
/* Reads sysctls, /proc/mounts, and the Docker socket: Linux only. */
/* ------------------------------------------------------- kernel remediation */

/* Byte-for-byte the profile sentinel/core/remediation.py generates. The em
 * dash in the banner is escaped so the emitted bytes match regardless of the
 * encoding of this source file. */
static char *generate_hardening_conf(void)
{
    buf_t b; buf_init(&b);
    buf_puts(&b,
        "# ====================================================================\n"
        "# Sentinel Cyber Agent \xe2\x80\x94 Autonomous Server 0-Day & Exploit Hardening\n"
        "# Generated automatically. Prevents memory corruption & privilege escalation.\n"
        "# ====================================================================\n"
        "\n");
    for (size_t i = 0; i < NELEM(FIX_PARAMS); i++) {
        if (i) buf_putc(&b, '\n');
        buf_printf(&b, "# %s\n%s = %s\n", FIX_PARAMS[i].desc, FIX_PARAMS[i].key, FIX_PARAMS[i].target);
    }
    return buf_release(&b);
}
#endif


#if defined(__linux__)
/* Reads sysctls, /proc/mounts, and the Docker socket: Linux only. */
static int env_flag(const char *name)
{
    const char *v = getenv(name);
    if (!v || !*v) return 0;
    if (str_ieq(v, "0") || str_ieq(v, "false") || str_ieq(v, "no") || str_ieq(v, "off")) return 0;
    return 1;
}
#endif


/* The --fix-kernel equivalent of sentinel/cli.py: apply the hardening profile.
 *
 * Two deliberate departures from the Python:
 *  - It never runs unprivileged. remediation.py relied on the sudo wrapper and
 *    reported permission_denied after the fact; here the check is up front.
 *  - Failures to write the persistence file do not abort the live /proc/sys
 *    writes. The live writes are the actual mitigation; the profile is only
 *    durability across reboots, so a missing /etc/sysctl.d must not cost the
 *    user the fix they asked for.
 *
 * Always returns 0: remediation trouble is reported as findings, never as a
 * plugin error. */
int host_harden_apply_fixes(orchestrator_t *ctx)
{
#if defined(__linux__)
    if (geteuid() != 0) {
        orch_note(ctx, PLUGIN_NAME, "kernel hardening skipped", HOST_TARGET,
                  "Fix mode requested but the process is not running as root "
                  "(geteuid != 0). Re-run with sudo to apply the hardening profile.");
        return 0;
    }

    /* Read every knob first: the plan and the writes must not interleave, or a
     * read could observe a value this same run just wrote. */
    char *current[NELEM(FIX_PARAMS)];
    for (size_t i = 0; i < NELEM(FIX_PARAMS); i++)
        current[i] = scrub(read_sysctl(FIX_PARAMS[i].proc_path));

    size_t compliant = 0, pending = 0, unreadable = 0;
    for (size_t i = 0; i < NELEM(FIX_PARAMS); i++) {
        if (!current[i]) { unreadable++; continue; }
        if (strcmp(current[i], FIX_PARAMS[i].target) == 0) compliant++;
        else pending++;
    }

    if (env_flag("SENTINEL_DRY_RUN")) {
        buf_t v, d; buf_init(&v); buf_init(&d);
        buf_printf(&v, "kernel hardening dry run: %lu of %lu parameters compliant",
                   (unsigned long)compliant, (unsigned long)NELEM(FIX_PARAMS));
        for (size_t i = 0; i < NELEM(FIX_PARAMS); i++) {
            if (!current[i] || strcmp(current[i], FIX_PARAMS[i].target) == 0) continue;
            buf_printf(&d, "%s%s%s: %s -> %s",
                       d.len ? "; " : "",
                       FIX_PARAMS[i].key,
                       current[i],
                       FIX_PARAMS[i].target);
        }
        if (pending) buf_printf(&d, ". Nothing was written (SENTINEL_DRY_RUN set).");
        else        buf_puts(&d, ". Nothing to change.");
        json_value_t *m = json_object();
        if (m) {
            json_object_set_num(m, "total_checked", (double)NELEM(FIX_PARAMS));
            json_object_set_num(m, "compliant_count", (double)compliant);
            json_object_set_num(m, "unreadable_count", (double)unreadable);
            json_object_set_str(m, "status", "dry_run");
        }
        emit(ctx, FT_HARDENING, SEV_INFO, v.data, d.data, m);
        buf_free(&v); buf_free(&d);
        goto done;
    }

    char *conf = generate_hardening_conf();
    if (conf && write_file(SYSCTL_CONF_PATH, conf, strlen(conf)) != 0) {
        buf_t d; buf_init(&d);
        buf_printf(&d, "Could not write the persistence profile %s. Live /proc/sys "
                       "values are still being applied, but the settings will not "
                       "survive a reboot.", SYSCTL_CONF_PATH);
        orch_note(ctx, PLUGIN_NAME, "hardening profile not persisted", HOST_TARGET, d.data);
        buf_free(&d);
    }
    free(conf);

    size_t applied = 0;
    for (size_t i = 0; i < NELEM(FIX_PARAMS); i++) {
        if (!current[i] || strcmp(current[i], FIX_PARAMS[i].target) == 0) continue;
        if (write_file(FIX_PARAMS[i].proc_path, FIX_PARAMS[i].target,
                       strlen(FIX_PARAMS[i].target)) != 0) {
            buf_t d; buf_init(&d);
            buf_printf(&d, "Failed to write %s = %s to %s. The kernel may not expose "
                           "this knob on this build, or it is locked by a live "
                           "container namespace.", FIX_PARAMS[i].key, FIX_PARAMS[i].target,
                       FIX_PARAMS[i].proc_path);
            orch_note(ctx, PLUGIN_NAME, "hardening write failed", HOST_TARGET, d.data);
            buf_free(&d);
            continue;
        }
        applied++;
        char *value = kv(FIX_PARAMS[i].key, FIX_PARAMS[i].target);
        emit_mitigation(ctx, SEV_INFO, value, FIX_PARAMS[i].desc,
                        FIX_PARAMS[i].key, FIX_PARAMS[i].target, "applied");
        free(value);
    }

    /* Reload so the on-disk profile and the live values agree. argv array, no
     * shell, so nothing here can be re-interpreted. */
    char out[256];
    char *sargv[] = { "sysctl", "--system", NULL };
    int rc = proc_run(sargv, out, sizeof(out), 10);
    if (rc != 0) {
        buf_t d; buf_init(&d);
        buf_printf(&d, "'sysctl --system' exited with status %d. The live /proc/sys "
                       "values were already written, but the profile in %s may not "
                       "have been reloaded for interfaces created later.", rc, SYSCTL_CONF_PATH);
        orch_note(ctx, PLUGIN_NAME, "sysctl reload failed", HOST_TARGET, d.data);
        buf_free(&d);
    }

    {
        buf_t v, d; buf_init(&v); buf_init(&d);
        buf_printf(&v, "Applied kernel hardening profile: %lu/%lu mitigations",
                   (unsigned long)applied, (unsigned long)pending);
        buf_printf(&d, "Wrote %s and %lu live /proc/sys value%s. "
                       "Re-run the audit to confirm the new posture.",
                   SYSCTL_CONF_PATH, (unsigned long)applied, applied == 1 ? "" : "s");
        json_value_t *m = json_object();
        if (m) {
            json_object_set_str(m, "conf_path", SYSCTL_CONF_PATH);
            json_object_set_num(m, "applied_count", (double)applied);
            json_object_set_num(m, "compliant_count", (double)compliant);
            json_object_set_num(m, "total_checked", (double)NELEM(FIX_PARAMS));
        }
        emit(ctx, FT_HARDENING, SEV_INFO, v.data, d.data, m);
        buf_free(&v); buf_free(&d);
    }

done:
    for (size_t i = 0; i < NELEM(FIX_PARAMS); i++) free(current[i]);
#else
    orch_note(ctx, PLUGIN_NAME, "kernel hardening skipped", HOST_TARGET,
              "Kernel hardening remediation requires Linux /proc/sys.");
#endif
    return 0;
}

/* ----------------------------------------------------------------- the audit */

#if !defined(__linux__)
static const char *PLATFORM_NAME = "posix";
#endif

/* Both this plugin and process_anomaly audit the machine they execute on, so a
 * remote target only means "skip" unless the caller flagged a server audit.
 * Preserved from the Python's run() guard in both plugins. */
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

    /* sshd_config hardening applies wherever OpenSSH is installed, which
     * includes macOS, so this check is not behind the platform guard. */
    audit_sshd(ctx);

#if defined(__linux__)
    audit_kernel(ctx);
    audit_mounts(ctx);
    audit_container(ctx);
    /* SENTINEL_FIX_KERNEL is the plugin-side equivalent of the Python CLI's
     * --fix-kernel flag, which remediation.py handled outside the plugin. The
     * plugin interface carries no flags, so the CLI sets the environment
     * variable; SENTINEL_DRY_RUN then downgrades it to a plan. */
    if (env_flag("SENTINEL_FIX_KERNEL"))
        host_harden_apply_fixes(ctx);
#else
    buf_t v, d; buf_init(&v); buf_init(&d);
    buf_printf(&v, "OS Platform: %s", PLATFORM_NAME);
    buf_printf(&d, "Platform %s detected. Kernel sysctl audit skipped.", PLATFORM_NAME);
    json_value_t *m = json_object();
    if (m) json_object_set_str(m, "platform", PLATFORM_NAME);
    emit(ctx, FT_HARDENING, SEV_INFO, v.data, d.data, m);
    buf_free(&v); buf_free(&d);
#endif
    return 0;
}

const plugin_t host_harden_plugin = {
    PLUGIN_NAME,
    "Audit kernel exploit mitigations, memory protections, and mount security for 0-day resilience",
    STAGE_AUDIT,
    { NULL },
    run
};
