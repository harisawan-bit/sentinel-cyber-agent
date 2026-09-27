/* sarif.c — SARIF 2.1.0 export.
 *
 * Ported from sentinel/core/sarif.py. Emits the subset of SARIF that GitHub
 * code scanning ingests: one result per finding, with severity mapped to the
 * SARIF level vocabulary.
 */
#include "sentinel/sarif.h"
#include "sentinel/buf.h"
#include "sentinel/util.h"
#include "sentinel/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* SARIF levels are a coarser vocabulary than Sentinel's six severities. */
static const char *sarif_level(severity_t s)
{
    switch (s) {
        case SEV_CRITICAL:
        case SEV_HIGH:    return "error";
        case SEV_MEDIUM:  return "warning";
        case SEV_LOW:     return "note";
        case SEV_INFO:
        case SEV_UNKNOWN:
        default:          return "none";
    }
}

json_value_t *sarif_build(const orchestrator_t *o, const char *tool_name)
{
    const char *name = (tool_name && *tool_name) ? tool_name : "sentinel";

    json_value_t *root = json_object();
    if (!root) return NULL;
    json_object_set_str(root, "$schema",
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
    json_object_set_str(root, "version", "2.1.0");

    /* driver */
    json_value_t *driver = json_object();
    json_object_set_str(driver, "name", name);
    json_object_set_str(driver, "informationUri",
                        "https://github.com/harisawan-bit/sentinel-cyber-agent");
    json_value_t *semver = json_object();
    json_object_set_str(semver, "name", name);
    json_object_set_str(semver, "version", SENTINEL_VERSION);
    json_object_set(driver, "semanticVersion", semver);

    /* results */
    json_value_t *results = json_array();
    for (const finding_t *f = o ? o->findings : NULL; f; f = f->next) {
        json_value_t *res = json_object();
        json_object_set_str(res, "ruleId", f->tool ? f->tool : "sentinel");

        json_value_t *lvl = json_object();
        json_object_set_str(lvl, "level", sarif_level(f->severity));
        json_object_set(res, "level", lvl);

        json_value_t *msg = json_object();
        const char *body = (f->detail && *f->detail) ? f->detail : f->value;
        char *text = sstrdup(finding_type_str(f->type));
        char *joined = NULL;
        if (text && body) {
            size_t n = strlen(text) + strlen(body) + 3;
            joined = malloc(n);
            if (joined) snprintf(joined, n, "%s: %s", text, body);
        }
        json_object_set_str(msg, "text", joined ? joined : (body ? body : ""));
        free(joined);
        free(text);
        json_object_set(res, "message", msg);

        json_value_t *phys = json_object();
        json_object_set_str(phys, "artifactLocation",
                            (f->target && *f->target) ? f->target : "local");
        json_value_t *loc = json_object();
        json_object_set(loc, "physicalLocation", phys);
        json_object_set(res, "locations", loc);

        json_value_t *props = json_object();
        json_object_set_str(props, "severity", severity_str(f->severity));
        json_object_set_str(props, "finding_type", finding_type_str(f->type));
        json_object_set_str(props, "value", f->value ? f->value : "");
        json_object_set_str(props, "id", f->id);
        /* Deep copy: the caller frees the orchestrator's findings after this
         * document, and the SARIF tree must not alias them. */
        if (f->metadata) {
            char *md = json_dump(f->metadata, 0);
            if (md) {
                json_object_set(props, "metadata", json_parse(md, strlen(md)));
                free(md);
            }
        }
        json_object_set(res, "properties", props);

        json_array_push(results, res);
    }

    /* run */
    json_value_t *toolobj = json_object();
    json_object_set(toolobj, "driver", driver);
    json_value_t *run = json_object();
    json_object_set(run, "tool", toolobj);
    json_object_set(run, "results", results);

    json_value_t *runs = json_array();
    json_array_push(runs, run);
    json_object_set(root, "runs", runs);
    return root;
}
