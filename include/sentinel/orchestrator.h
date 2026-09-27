/* sentinel/orchestrator.h — pipeline runner and cross-plugin state. */
#ifndef SENTINEL_ORCHESTRATOR_H
#define SENTINEL_ORCHESTRATOR_H

#include "sentinel/model.h"
#include "sentinel/plugin.h"

typedef struct orchestrator {
    finding_t   *findings;      /* head of the accumulated list */
    char        *shared_techs[64];
    size_t       tech_count;
    int          server_audit;  /* relax target gating for host-only plugins */

    /* Current invocation context, set by orch_run(). */
    const char  *cur_target;
} orchestrator_t;

orchestrator_t *orch_new(void);
void orch_free(orchestrator_t *o);

void orch_add(orchestrator_t *o, finding_t *f);

/* Record a free-form note (used for skip/error paths). */
void orch_note(orchestrator_t *o, const char *tool, const char *value,
               const char *target, const char *detail);

/* Which external binaries a plugin needs that are not installed. */
size_t orch_missing_requirements(const plugin_t *p, const char *out[]);

/* Run the pipeline. `targets` is NULL-terminated. `stages` may be NULL for all,
 * or a bitmask of 1 << stage_t. */
void orch_run(orchestrator_t *o, const char *const *targets,
              unsigned stage_mask);

/* Serialize all findings as a JSON array (caller frees). */
json_value_t *orch_findings_json(const orchestrator_t *o);

#endif /* SENTINEL_ORCHESTRATOR_H */
