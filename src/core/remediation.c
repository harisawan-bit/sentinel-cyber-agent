/* remediation.c — kernel hardening profile planner/applier.
 *
 * Ported from sentinel/core/remediation.py. Reads the current sysctl values,
 * plans the deltas, and can either preview them (dry run) or write them.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/remediation.h"
#include "sentinel/buf.h"
#include "sentinel/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The hardening profile. Kept in one table so the plan, the preview, and the
 * applied sysctl writes can never drift apart. */
typedef struct {
    const char *param;       /* sysctl key, as used in the conf file */
    const char *proc_path;   /* /proc/sys equivalent */
    const char *target;      /* required value */
    const char *description;
} rule_t;

static const rule_t PROFILE[] = {
    { "kernel.randomize_va_space", "/proc/sys/kernel/randomize_va_space", "2",
      "Full ASLR defeats pointer-prediction exploitation" },
    { "kernel.kptr_restrict",       "/proc/sys/kernel/kptr_restrict",       "2",
      "Hide kernel pointers from unprivileged users" },
    { "kernel.dmesg_restrict",      "/proc/sys/kernel/dmesg_restrict",      "1",
      "Restrict kernel log access" },
    { "fs.protected_symlinks",      "/proc/sys/fs/protected_symlinks",      "1",
      "Block symlink attacks in sticky directories" },
    { "fs.protected_hardlinks",     "/proc/sys/fs/protected_hardlinks",     "1",
      "Block hardlink attacks in sticky directories" },
};
#define NUM_RULES ((int)(sizeof(PROFILE) / sizeof(PROFILE[0])))

static const char *CONF_PATH = "/etc/sysctl.d/99-sentinel-hardening.conf";

char *remediation_conf_preview(void)
{
    buf_t b; buf_init(&b);
    for (int i = 0; i < NUM_RULES; i++)
        buf_printf(&b, "%s = %s\n", PROFILE[i].param, PROFILE[i].target);
    return buf_release(&b);
}

int remediation_apply(int dry_run)
{
    char *prev_preview = remediation_conf_preview();

    buf_t applied; buf_init(&applied);
    int compliant = 0, applied_count = 0, total = NUM_RULES;

    for (int i = 0; i < NUM_RULES; i++) {
        char *cur = read_sysctl(PROFILE[i].proc_path);
        if (cur && strcmp(cur, PROFILE[i].target) == 0) {
            compliant++;
            free(cur);
            continue;
        }
        free(cur);

        if (dry_run) {
            /* Show the delta without touching anything. */
            char *now_val = read_sysctl(PROFILE[i].proc_path);
            printf("    [MOD] %s: %s -> %s (%s)\n", PROFILE[i].param,
                   now_val ? now_val : "(unreadable)", PROFILE[i].target,
                   PROFILE[i].description);
            free(now_val);
            continue;
        }

        if (geteuid() != 0) {
            printf("    [SKIP] %s: requires root\n", PROFILE[i].param);
            continue;
        }
        /* Writing /proc/sys applies immediately; argv-free and shell-free. */
        if (write_file(PROFILE[i].proc_path, PROFILE[i].target,
                       strlen(PROFILE[i].target)) == 0) {
            applied_count++;
            if (applied.len) buf_puts(&applied, ", ");
            buf_puts(&applied, PROFILE[i].param);
        } else {
            printf("    [FAIL] %s: could not write %s\n",
                   PROFILE[i].param, PROFILE[i].proc_path);
        }
    }

    if (!dry_run && applied_count) {
        /* Persist the profile so it survives a reboot. */
        FILE *cf = fopen(CONF_PATH, "w");
        if (cf) {
            fputs(prev_preview, cf);
            fclose(cf);
        }
    }

    if (applied.len) printf("    [OK] applied: %s\n", applied.data);
    printf("[+] Total compliant: %d/%d\n", compliant + applied_count, total);
    printf("    -> %s\n", CONF_PATH);

    buf_free(&applied);
    free(prev_preview);
    return applied_count;
}
