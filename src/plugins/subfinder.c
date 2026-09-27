/* subfinder.c — passive subdomain enumeration via projectdiscovery/subfinder.
 *
 * Ported from sentinel/core/plugins/subfinder_plugin.py. A thin wrapper: the
 * heavy lifting is the external MIT-licensed binary, and this file only
 * resolves it, runs it, and turns each output line into a subdomain finding.
 *
 * The command is passed to proc_capture() as a char *argv[] and executed with
 * execvp, never as a shell string. The target is operator-supplied, but a
 * string-built command would let a stray `;` or backtick in it be interpreted;
 * argv keeps it inert.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/sentinel.h"
#include "sentinel/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME     "subfinder"
#define BIN      "subfinder"
/* Python's subprocess.run(timeout=300). proc_capture does not enforce a
 * deadline yet, so this is documentary rather than load-bearing. */
#define TIMEOUT  300

static int run(orchestrator_t *ctx, const char *target)
{
    /* The orchestrator normally skips us before run() when requires[] is
     * unmet, but run() is also reachable directly (tests, embedders), so the
     * Python's own guard is kept here. */
    if (!bin_available(BIN)) {
        orch_note(ctx, NAME, "subfinder not installed (run scripts/install_engines.py)",
                  target, NULL);
        return 0;
    }

    /* bin_path() returns a static buffer valid only until the next call, so
     * copy it before the argv array outlives the expression. */
    char *bin = sstrdup(bin_path(BIN));
    if (!bin) {
        orch_note(ctx, NAME, "error: out of memory", target, NULL);
        return 0;
    }

    char *argv[] = { bin, "-d", (char *)target, "-silent", NULL };
    size_t out_len = 0;
    char *out = proc_capture(argv, &out_len, TIMEOUT);
    free(bin);

    if (!out) {
        orch_note(ctx, NAME, "error: subfinder could not be executed", target, NULL);
        return 0;
    }

    /* Python: for line in r.stdout.splitlines(): s = line.strip(); if s: yield.
     * proc_capture merges stderr into the same pipe, so lines that are not
     * subdomains (progress chatter, warnings) are filtered by requiring a dot
     * and no leading bracket — subfinder never emits a bare hostname. */
    char *p = out;
    while (*p) {
        char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);

        char line[1024];
        if (len < sizeof(line)) {
            memcpy(line, p, len);
            line[len] = '\0';
            str_trim(line);
            if (line[0] && line[0] != '[' && strchr(line, '.')) {
                finding_t *f = finding_new(NAME, FT_SUBDOMAIN, line, target, SEV_INFO);
                if (f) orch_add(ctx, f);
            }
        }
        if (!nl) break;
        p = nl + 1;
    }

    free(out);
    return 0;
}

const plugin_t subfinder_plugin = {
    "subfinder",
    "Passive subdomain enumeration (projectdiscovery/subfinder, MIT)",
    STAGE_RECON,
    { "subfinder", NULL },
    run
};
