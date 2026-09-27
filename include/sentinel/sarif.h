#ifndef SENTINEL_SARIF_H
#define SENTINEL_SARIF_H

#include "sentinel/json.h"
#include "sentinel/orchestrator.h"

/* Build a SARIF 2.1.0 document for the accumulated findings. */
json_value_t *sarif_build(const orchestrator_t *o, const char *tool_name);

#endif /* SENTINEL_SARIF_H */
