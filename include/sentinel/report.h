#ifndef SENTINEL_REPORT_H
#define SENTINEL_REPORT_H

#include "sentinel/json.h"
#include "sentinel/orchestrator.h"

/* Render the findings as a standalone HTML document. Caller frees. */
char *report_render(const orchestrator_t *o, const char *title);

/* Render a pre-built JSON array of findings (the shape the CLI passes around). */
char *report_render_json(const json_value_t *findings, const char *title);

#endif /* SENTINEL_REPORT_H */
