/* httpx.c — live host probing via projectdiscovery/httpx.
 *
 * Ported from sentinel/core/plugins/httpx_plugin.py. Also a thin wrapper: the
 * binary does the probing, this parses its `-json` line stream into host
 * findings. Like subfinder, the command goes to proc_capture() as a char
 * *argv[] and reaches execvp, never as a shell string.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/sentinel.h"
#include "sentinel/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME    "httpx"
#define BIN     "httpx"
/* Python's subprocess.run(timeout=300); proc_capture does not yet enforce a
 * deadline, so this is documentary rather than load-bearing. */
#define TIMEOUT 300

/* httpx emits one JSON object per line. Only these keys are carried into the
 * finding metadata, matching the Python's explicit key list. */
static const char *META_KEYS[] = { "status_code", "title", "tech", "webserver", "scheme" };
#define N_META_KEYS (sizeof(META_KEYS) / sizeof(META_KEYS[0]))

/* json_object_set() takes ownership of the value it is handed, so the parsed
 * per-line object cannot be grafted into a finding's metadata — it would be
 * freed twice when both the finding and the parse tree are released. Deep-copy
 * instead. The "tech" value is an array, so this has to recurse. */
static json_value_t *clone_value(const json_value_t *v)
{
    if (!v) return NULL;
    switch (v->type) {
    case JSON_NULL:   return json_null();
    case JSON_BOOL:   return json_bool(v->boolean);
    case JSON_NUMBER: return json_number(v->number);
    case JSON_STRING: return json_string(v->string ? v->string : "");
    case JSON_ARRAY: {
        json_value_t *a = json_array();
        if (!a) return NULL;
        for (size_t i = 0; i < v->count; i++) json_array_push(a, clone_value(v->items[i]));
        return a;
    }
    case JSON_OBJECT: {
        json_value_t *o = json_object();
        if (!o) return NULL;
        for (size_t i = 0; i < v->count; i++)
            if (v->keys) json_object_set(o, v->keys[i], clone_value(v->items[i]));
        return o;
    }
    }
    return json_null();
}

static int run(orchestrator_t *ctx, const char *target)
{
    if (!bin_available(BIN)) {
        orch_note(ctx, NAME, "httpx not installed (run scripts/install_engines.py)",
                  target, NULL);
        return 0;
    }

    char *bin = sstrdup(bin_path(BIN));
    if (!bin) {
        orch_note(ctx, NAME, "error: out of memory", target, NULL);
        return 0;
    }

    char *argv[] = { bin, "-u", (char *)target, "-silent", "-json", NULL };
    size_t out_len = 0;
    char *out = proc_capture(argv, &out_len, TIMEOUT);
    free(bin);

    if (!out) {
        orch_note(ctx, NAME, "error: httpx could not be executed", target, NULL);
        return 0;
    }

    char *p = out;
    while (*p) {
        char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);

        char line[65536];
        if (len < sizeof(line)) {
            memcpy(line, p, len);
            line[len] = '\0';
            str_trim(line);
            if (line[0]) {
                json_value_t *d = json_parse(line, strlen(line));
                /* Python: try/except around json.loads, continue on failure.
                 * proc_capture merges stderr, so non-JSON lines are expected. */
                if (d && d->type == JSON_OBJECT) {
                    /* Python: d.get("status_code", 0) >= 400 -> LOW. A
                     * missing or non-numeric status_code stays INFO. */
                    severity_t sev = SEV_INFO;
                    json_value_t *sc = json_get(d, "status_code");
                    if (sc && sc->type == JSON_NUMBER && sc->number >= 400)
                        sev = SEV_LOW;

                    const char *url = json_get_str(d, "url");
                    if (!url) url = target;

                    /* Python: {k: d.get(k) for k in (...) if k in d} — keys
                     * absent from the object are omitted, not nulled. */
                    json_value_t *meta = json_object();
                    for (size_t i = 0; i < N_META_KEYS; i++) {
                        json_value_t *v = json_get(d, META_KEYS[i]);
                        if (v) json_object_set(meta, META_KEYS[i], clone_value(v));
                    }

                    finding_t *f = finding_new(NAME, FT_HOST, url, target, sev);
                    if (f) {
                        finding_set_meta(f, meta);
                        orch_add(ctx, f);
                    } else {
                        json_free(meta);
                    }
                }
                json_free(d);
            }
        }
        if (!nl) break;
        p = nl + 1;
    }

    free(out);
    return 0;
}

const plugin_t httpx_plugin = {
    "httpx",
    "Live host probing + tech detection (projectdiscovery/httpx, MIT)",
    STAGE_RECON,
    { "httpx", NULL },
    run
};
