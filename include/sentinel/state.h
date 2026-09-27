#ifndef SENTINEL_STATE_H
#define SENTINEL_STATE_H

#include "sentinel/json.h"

/* Compare `current` against the stored baseline. Returns a JSON array of
 * drift findings (empty on first run). Caller frees. */
json_value_t *state_diff(const json_value_t *current);

/* Persist the current finding set as the new baseline. */
int state_update(const json_value_t *current);

#endif /* SENTINEL_STATE_H */
