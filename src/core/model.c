/* model.c — Finding lifecycle and (de)serialization. */
#include "sentinel/model.h"
#include "sentinel/buf.h"
#include "sentinel/util.h"

#include <stdlib.h>
#include <string.h>

static const char *SEV_NAMES[] = { "info", "low", "medium", "high", "critical", "unknown" };

/* Matches the Python enum values exactly; these strings are what lands in
 * SARIF level fields and report output. */
static const char *FT_NAMES[FT__COUNT] = {
    "subdomain", "host", "port", "technology", "vulnerability", "misconfiguration",
    "account", "cloud_resource", "hardening", "anomaly", "threat_intel", "canary",
    "integrity", "deception", "remediation", "note"
};

const char *severity_str(severity_t s)
{
    if (s < 0 || s > SEV_UNKNOWN) return "unknown";
    return SEV_NAMES[s];
}

severity_t severity_parse(const char *s)
{
    if (!s) return SEV_UNKNOWN;
    for (int i = 0; i <= SEV_UNKNOWN; i++)
        if (str_ieq(s, SEV_NAMES[i])) return (severity_t)i;
    return SEV_UNKNOWN;
}

const char *finding_type_str(finding_type_t t)
{
    if (t < 0 || t >= FT__COUNT) return "note";
    return FT_NAMES[t];
}

finding_type_t finding_type_parse(const char *s)
{
    if (!s) return FT_NOTE;
    for (int i = 0; i < FT__COUNT; i++)
        if (str_ieq(s, FT_NAMES[i])) return (finding_type_t)i;
    return FT_NOTE;
}

finding_t *finding_new(const char *tool, finding_type_t type, const char *value,
                       const char *target, severity_t sev)
{
    finding_t *f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    f->tool = tool;
    f->type = type;
    f->value = sstrdup(value ? value : "");
    f->target = sstrdup(target ? target : "");
    f->severity = sev;
    f->timestamp = now_seconds();
    f->next = NULL;

    /* 12 hex chars, matching the Python id() style short id. */
    char *hex = random_hex(6);
    if (hex) {
        snprintf(f->id, sizeof(f->id), "%.12s", hex);
        free(hex);
    }
    return f;
}

void finding_set_detail(finding_t *f, const char *detail)
{
    if (!f) return;
    free(f->detail);
    f->detail = sstrdup(detail);
}

void finding_set_meta(finding_t *f, json_value_t *meta)
{
    if (!f) { json_free(meta); return; }
    json_free(f->metadata);
    f->metadata = meta;
}

void finding_free(finding_t *f)
{
    if (!f) return;
    free(f->value);
    free(f->target);
    free(f->detail);
    json_free(f->metadata);
    free(f);
}

void finding_list_free(finding_t *head)
{
    while (head) {
        finding_t *next = head->next;
        finding_free(head);
        head = next;
    }
}

json_value_t *finding_to_json(const finding_t *f)
{
    if (!f) return NULL;
    json_value_t *o = json_object();
    if (!o) return NULL;
    json_object_set_str(o, "id", f->id);
    json_object_set_str(o, "tool", f->tool ? f->tool : "");
    json_object_set_str(o, "finding_type", finding_type_str(f->type));
    json_object_set_str(o, "value", f->value);
    json_object_set_str(o, "target", f->target);
    json_object_set_str(o, "severity", severity_str(f->severity));
    if (f->detail) json_object_set_str(o, "detail", f->detail);
    /* Metadata is deep-copied, not shared: several findings are routinely
     * built from the same module-level JSON object, and handing out the
     * original pointer would make the result tree alias live finding state.
     * Whoever frees the tree first would then free memory the other findings
     * still reference. */
    if (f->metadata) {
        char *dump = json_dump(f->metadata, 0);
        if (dump) {
            json_object_set(o, "metadata", json_parse(dump, strlen(dump)));
            free(dump);
        }
    }
    json_object_set_num(o, "timestamp", f->timestamp);
    return o;
}

finding_t *finding_from_json(const json_value_t *v)
{
    if (!v || v->type != JSON_OBJECT) return NULL;
    finding_t *f = finding_new(json_get_str(v, "tool"),
                              finding_type_parse(json_get_str(v, "finding_type")),
                              json_get_str(v, "value"),
                              json_get_str(v, "target"),
                              severity_parse(json_get_str(v, "severity")));
    if (!f) return NULL;
    const char *d = json_get_str(v, "detail");
    if (d) finding_set_detail(f, d);
    /* metadata is deep-copied so the source tree can be freed independently */
    json_value_t *m = json_get(v, "metadata");
    if (m) {
        char *dump = json_dump(m, 0);
        if (dump) {
            finding_set_meta(f, json_parse(dump, strlen(dump)));
            free(dump);
        }
    }
    json_value_t *ts = json_get(v, "timestamp");
    if (ts && ts->type == JSON_NUMBER) f->timestamp = ts->number;
    const char *id = json_get_str(v, "id");
    if (id) snprintf(f->id, sizeof(f->id), "%.12s", id);
    return f;
}
