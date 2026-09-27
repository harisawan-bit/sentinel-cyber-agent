/* orchestrator.c — pipeline execution and finding accumulation. */
#include "sentinel/orchestrator.h"
#include "sentinel/buf.h"
#include "sentinel/config.h"
#include "sentinel/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *STAGE_NAMES[STAGE__COUNT] = {
    "recon", "scan", "osint", "cloud", "audit", "intel"
};

const char *stage_str(stage_t s)
{
    if (s < 0 || s >= STAGE__COUNT) return "recon";
    return STAGE_NAMES[s];
}

stage_t stage_parse(const char *s)
{
    if (!s) return STAGE_RECON;
    for (int i = 0; i < STAGE__COUNT; i++)
        if (str_ieq(s, STAGE_NAMES[i])) return (stage_t)i;
    return STAGE_RECON;
}

orchestrator_t *orch_new(void)
{
    return calloc(1, sizeof(orchestrator_t));
}

void orch_free(orchestrator_t *o)
{
    if (!o) return;
    finding_list_free(o->findings);
    free(o);
}

void orch_add(orchestrator_t *o, finding_t *f)
{
    if (!o || !f) { finding_free(f); return; }
    /* Append at the tail so report ordering matches run ordering. */
    if (!o->findings) {
        o->findings = f;
        return;
    }
    finding_t *cur = o->findings;
    while (cur->next) cur = cur->next;
    cur->next = f;

    /* Harvest tech tokens from host findings so the OSV correlation stage can
     * consume them, mirroring the Python cross-plugin `shared` dict. */
    if (f->type == FT_HOST && f->metadata) {
        json_value_t *tech = json_get(f->metadata, "tech");
        for (size_t i = 0; tech && i < json_len(tech); i++) {
            const char *raw = json_str_at(tech, i);
            if (!raw) continue;
            const char *token = raw;
            const char *eq = strchr(raw, '=');
            if (eq) token = eq + 1;
            char low[128];
            str_lower(token, low, sizeof(low));
            if (!low[0] || o->tech_count >= sizeof(o->shared_techs) / sizeof(o->shared_techs[0]))
                continue;
            int seen = 0;
            for (size_t j = 0; j < o->tech_count; j++)
                if (strcmp(o->shared_techs[j], low) == 0) { seen = 1; break; }
            if (!seen) o->shared_techs[o->tech_count++] = sstrdup(low);
        }
    }
}

void orch_note(orchestrator_t *o, const char *tool, const char *value,
               const char *target, const char *detail)
{
    finding_t *f = finding_new(tool, FT_NOTE, value, target, SEV_INFO);
    if (!f) return;
    if (detail) finding_set_detail(f, detail);
    orch_add(o, f);
}

size_t orch_missing_requirements(const plugin_t *p, const char *out[])
{
    if (!p) return 0;
    size_t n = 0;
    for (int i = 0; i < 4 && p->requires[i]; i++) {
        if (!bin_available(p->requires[i]) && n < 8) out[n++] = p->requires[i];
    }
    return n;
}

void orch_run(orchestrator_t *o, const char *const *targets, unsigned stage_mask)
{
    if (!o || !targets) return;

    size_t count = 0;
    const plugin_t *plugins = sentinel_plugin_list(&count);
    if (!plugins || !count) return;

    for (int ti = 0; targets[ti]; ti++) {
        const char *target = targets[ti];
        o->cur_target = target;

        /* Stage order is the pipeline contract: recon feeds scan feeds audit.
         * Within a stage, registry order is preserved. */
        for (stage_t st = STAGE_RECON; st < STAGE__COUNT; st++) {
            if (stage_mask && !(stage_mask & (1u << (unsigned)st))) continue;

            for (size_t i = 0; i < count; i++) {
                const plugin_t *p = &plugins[i];
                if (p->stage != st) continue;

                const char *missing[8];
                size_t nmissing = orch_missing_requirements(p, missing);
                if (nmissing) {
                    buf_t v, d;
                    buf_init(&v); buf_init(&d);
                    buf_printf(&v, "%s skipped: missing ", p->name);
                    for (size_t k = 0; k < nmissing; k++)
                        buf_printf(&v, "%s%s", k ? ", " : "", missing[k]);
                    buf_printf(&d,
                               "Plugin '%s' requires %s. Run scripts/install_engines.py "
                               "or install manually.",
                               p->name,
                               nmissing == 1 ? missing[0] : "these binaries");
                    orch_note(o, p->name, v.data, target, d.data);
                    buf_free(&v); buf_free(&d);
                    continue;
                }

                int rc = p->run ? p->run(o, target) : 0;
                if (rc != 0) {
                    /* A plugin failure is a note, never a crash: the rest of the
                     * pipeline still runs and the reason is recorded. */
                    buf_t d; buf_init(&d);
                    buf_printf(&d, "Plugin '%s' exited with status %d during the %s stage.",
                               p->name, rc, stage_str(st));
                    orch_note(o, p->name, "plugin error", target, d.data);
                    buf_free(&d);
                }
            }
        }
    }
    o->cur_target = NULL;
}

json_value_t *orch_findings_json(const orchestrator_t *o)
{
    json_value_t *arr = json_array();
    if (!arr || !o) return arr;
    for (const finding_t *f = o->findings; f; f = f->next)
        json_array_push(arr, finding_to_json(f));
    return arr;
}
