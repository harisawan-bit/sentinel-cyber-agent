/* sqlmap.c — port of SqlmapExternalPlugin
 * (sentinel/core/plugins/sqlmap_external_plugin.py).
 *
 * LICENSE ISOLATION: sqlmap is GPL-2.0. It is never imported, vendored or
 * linked — the plugin only execs the binary as a separate OS process and
 * parses what it prints, so the GPL terms stay confined to that subprocess and
 * the MIT core stays clean.
 *
 * Install separately (pip install sqlmap, or clone upstream) and put it on
 * PATH; the orchestrator skips this plugin when it is missing.
 */
#include "sentinel/sentinel.h"
#include "sentinel/config.h"   /* bin_path(), bin_available() */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define PLUGIN_NAME "sqlmap-external"
#define SQLMAP_TIMEOUT 600   /* Python subprocess timeout=600 */

/* Python _SEV plus `_SEV.get(group, Severity.INFO)`: unknown tags are INFO,
 * so severity_parse() is deliberately not used (it yields SEV_UNKNOWN). */
static severity_t sqlmap_severity(const char *tag)
{
    if (!tag) return SEV_INFO;
    if (str_ieq(tag, "low")) return SEV_LOW;
    if (str_ieq(tag, "medium")) return SEV_MEDIUM;
    if (str_ieq(tag, "high")) return SEV_HIGH;
    if (str_ieq(tag, "critical")) return SEV_CRITICAL;
    return SEV_INFO;
}

static int is_word(char c)
{
    return isalnum((unsigned char)c) || c == '_';
}

/* Python: re.finditer(r"\[(\w+)\]\s+(.*)", out), one Finding per match.
 * Walks the buffer the way re.finditer does — left to right, resuming after
 * the end of the previous match — so overlapping brackets are not re-reported.
 * proc_capture() merges stdout and stderr, which is what `r.stdout + r.stderr`
 * assembled in the original. */
static void scan_output(orchestrator_t *ctx, const char *target, const char *out)
{
    const char *p = out;
    while (*p) {
        if (*p != '[') { p++; continue; }

        const char *tag = p + 1;
        if (!*tag || !is_word(*tag)) { p++; continue; }   /* \w+ needs one */
        while (is_word(*tag)) tag++;
        if (*tag != ']') { p++; continue; }

        /* \s+ is greedy and spans newlines in the original regex, so the
         * payload may begin on the line after the tag; `.` never does. */
        const char *payload = tag + 1;
        while (*payload == ' ' || *payload == '\t' || *payload == '\r' ||
               *payload == '\n' || *payload == '\v' || *payload == '\f')
            payload++;

        const char *end = payload;
        while (*end && *end != '\n') end++;

        char *detail = sstrndup(payload, (size_t)(end - payload));
        str_trim(detail);
        if (strlen(detail) > 200) detail[200] = '\0';   /* Python: [:200] */

        char sev_tag[64];
        size_t taglen = (size_t)(tag - (p + 1));
        if (taglen >= sizeof sev_tag) taglen = sizeof sev_tag - 1;
        memcpy(sev_tag, p + 1, taglen);
        sev_tag[taglen] = '\0';

        finding_t *f = finding_new(PLUGIN_NAME, FT_VULNERABILITY, target, target,
                                   sqlmap_severity(sev_tag));
        if (f) {
            finding_set_detail(f, detail);
            orch_add(ctx, f);
        }
        free(detail);

        p = end;   /* resume after this match, like finditer */
    }
}

static int run(orchestrator_t *ctx, const char *target)
{
    if (!ctx || !target) return 0;

    /* requires[] names "sqlmap" so the orchestrator skips cleanly when the
     * engine is absent; Python additionally accepted a "sqlmap.py" on PATH,
     * which is kept as a fallback here. */
    const char *bin = NULL;
    if (bin_available("sqlmap")) bin = bin_path("sqlmap");
    else if (bin_available("sqlmap.py")) bin = bin_path("sqlmap.py");

    if (!bin) {
        orch_note(ctx, PLUGIN_NAME,
                  "sqlmap not installed (GPL-2.0 engine runs externally; install separately)",
                  target,
                  "Plugin 'sqlmap-external' invokes the sqlmap binary as an isolated "
                  "subprocess. Install sqlmap separately (pip install sqlmap or clone "
                  "upstream) to enable SQL injection detection.");
        return 0;
    }

    /* Results land in the Sentinel state dir rather than a hardcoded /tmp path:
     * SENTINEL_HOME relocates it, and the agent must not assume a writable
     * /tmp. Nothing here parses that directory — sqlmap owns its own output. */
    paths_ensure_dir();
    char outdir[1024];
    snprintf(outdir, sizeof outdir, "--output-dir=%s", paths_state_path("sqlmap"));

    /* argv, never a command string: `target` is operator-supplied and must not
     * be reinterpreted by a shell. */
    char *argv[] = {
        (char *)bin, "-u", (char *)target, "--batch", "--disable-coloring",
        "--level=1", "--risk=1", outdir, NULL
    };

    size_t out_len = 0;
    char *out = proc_capture(argv, &out_len, SQLMAP_TIMEOUT);
    if (!out) {
        orch_note(ctx, PLUGIN_NAME, "error: sqlmap could not be executed", target,
                  "proc_capture() failed to start sqlmap; SQL injection testing was skipped.");
        return 0;
    }

    scan_output(ctx, target, out);
    free(out);
    return 0;
}

const plugin_t sqlmap_plugin = {
    PLUGIN_NAME,
    "SQLi detection via sqlmap (GPL-2.0) — invoked as ISOLATED external process only",
    STAGE_SCAN,
    { "sqlmap", NULL },
    run
};
