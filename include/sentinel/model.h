/* sentinel/model.h — the Finding record shared by every plugin. */
#ifndef SENTINEL_MODEL_H
#define SENTINEL_MODEL_H

#include "sentinel/json.h"

typedef enum {
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL,
    SEV_UNKNOWN
} severity_t;

/* finding_type strings match the Python enum values exactly so SARIF and
 * report output stay byte-comparable with the previous implementation. */
typedef enum {
    FT_SUBDOMAIN = 0,
    FT_HOST,
    FT_PORT,
    FT_TECHNOLOGY,
    FT_VULNERABILITY,
    FT_MISCONFIGURATION,
    FT_ACCOUNT,
    FT_CLOUD_RESOURCE,
    FT_HARDENING,
    FT_ANOMALY,
    FT_THREAT_INTEL,
    FT_CANARY,
    FT_INTEGRITY,
    FT_DECEPTION,
    FT_REMEDIATION,
    FT_NOTE,
    FT__COUNT
} finding_type_t;

typedef struct finding {
    const char        *tool;
    finding_type_t     type;
    char              *value;
    char              *target;
    severity_t         severity;
    char              *detail;      /* may be NULL */
    json_value_t      *metadata;    /* owned; may be NULL */
    double             timestamp;
    char               id[13];      /* 12 hex chars + NUL */

    struct finding    *next;        /* single-linked list accumulator */
} finding_t;

const char *severity_str(severity_t s);
severity_t  severity_parse(const char *s);
const char *finding_type_str(finding_type_t t);
finding_type_t finding_type_parse(const char *s);

/* Allocate a finding with a freshly generated id and timestamp. */
finding_t *finding_new(const char *tool, finding_type_t type, const char *value,
                       const char *target, severity_t sev);
void finding_set_detail(finding_t *f, const char *detail);
void finding_set_meta(finding_t *f, json_value_t *meta); /* takes ownership */
void finding_free(finding_t *f);
void finding_list_free(finding_t *head);

/* Convert to a JSON object (caller frees). */
json_value_t *finding_to_json(const finding_t *f);

/* Build a Finding from a parsed JSON object (caller frees). */
finding_t *finding_from_json(const json_value_t *v);

#endif /* SENTINEL_MODEL_H */
