/* nuclei.c — port of NucleiPlugin
 * (sentinel/core/plugins/nuclei_plugin.py).
 *
 * Thin wrapper around the projectdiscovery/nuclei binary: run it in JSONL mode
 * and translate each line into a Finding. The engine stays an external process
 * (MIT, separately installed) so nothing of it is linked into sentineld.
 */
#include "sentinel/sentinel.h"
#include "sentinel/config.h"   /* bin_path(), bin_available() */

#include <stdlib.h>
#include <string.h>

#define PLUGIN_NAME "nuclei"
#define NUCLEI_TIMEOUT 600     /* Python subprocess timeout=600 */

/* Python _SEV plus `_SEV.get(d.get("severity", "info"), Severity.INFO)`: an
 * unrecognised severity falls back to INFO, not to SEV_UNKNOWN, so
 * severity_parse() (built for operator-supplied labels) is deliberately not
 * used here — it would change reported severities. */
static severity_t nuclei_severity(const char *sev)
{
    if (!sev) return SEV_INFO;
    if (str_ieq(sev, "low")) return SEV_LOW;
    if (str_ieq(sev, "medium")) return SEV_MEDIUM;
    if (str_ieq(sev, "high")) return SEV_HIGH;
    if (str_ieq(sev, "critical")) return SEV_CRITICAL;
    return SEV_INFO;
}

static void handle_line(orchestrator_t *ctx, const char *target, char *line)
{
    str_trim(line);
    if (!*line) return;

    json_value_t *d = json_parse(line, strlen(line));
    if (!d) return;   /* Python: `except Exception: continue` */

    const char *matched = json_get_str(d, "matched-at");
    finding_t *f = finding_new(PLUGIN_NAME, FT_VULNERABILITY,
                               (matched && *matched) ? matched : target,
                               target, nuclei_severity(json_get_str(d, "severity")));
    if (!f) { json_free(d); return; }

    /* info is a nested object; Python only reads it when it is a dict. */
    const json_value_t *info = json_get(d, "info");
    if (info && info->type == JSON_OBJECT) {
        const char *name = json_get_str(info, "name");
        if (name) finding_set_detail(f, name);
    }

    /* Python passes d.get(...) through as-is, so an absent key stays null in
     * the metadata rather than becoming an empty string. */
    json_value_t *meta = json_object();
    const char *tmpl = json_get_str(d, "template-id");
    const char *type = json_get_str(d, "type");
    json_object_set(meta, "template", tmpl ? json_string(tmpl) : json_null());
    json_object_set(meta, "type", type ? json_string(type) : json_null());
    finding_set_meta(f, meta);

    json_free(d);
    orch_add(ctx, f);
}

static int run(orchestrator_t *ctx, const char *target)
{
    if (!ctx || !target) return 0;

    /* requires[] already makes the orchestrator skip us when nuclei is
     * absent; re-checking keeps a direct invocation honest. */
    if (!bin_available(PLUGIN_NAME)) {
        orch_note(ctx, PLUGIN_NAME,
                  "nuclei not installed (run scripts/install_engines.py)", target,
                  "Plugin 'nuclei' shells out to the projectdiscovery nuclei binary. "
                  "Run scripts/install_engines.py or put nuclei on PATH to enable "
                  "template-based vulnerability scanning.");
        return 0;
    }

    /* argv, never a command string: `target` is operator-supplied and must not
     * be reinterpreted by a shell. */
    char *argv[] = {
        (char *)bin_path(PLUGIN_NAME), "-u", (char *)target,
        "-silent", "-json", "-severity", "low,medium,high,critical", NULL
    };

    size_t out_len = 0;
    char *out = proc_capture(argv, &out_len, NUCLEI_TIMEOUT);
    if (!out) {
        orch_note(ctx, PLUGIN_NAME, "error: nuclei could not be executed", target,
                  "proc_capture() failed to start nuclei; template scanning was skipped.");
        return 0;
    }

    /* One JSON object per line. proc_capture() merges stdout and stderr, so
     * the stray non-JSON lines the engine writes are dropped by the parse. */
    for (char *line = out; line && *line; ) {
        char *nl = strchr(line, '\n');
        if (!nl) { handle_line(ctx, target, line); break; }
        *nl = '\0';
        handle_line(ctx, target, line);
        line = nl + 1;
    }
    free(out);
    return 0;
}

const plugin_t nuclei_plugin = {
    PLUGIN_NAME,
    "Template-based vuln/misconfig scanning (projectdiscovery/nuclei, MIT)",
    STAGE_SCAN,
    { "nuclei", NULL },
    run
};
