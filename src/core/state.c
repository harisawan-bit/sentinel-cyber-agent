/* state.c — historical baseline and drift detection.
 *
 * Ported from sentinel/core/state.py. Compares the current finding set against
 * the previous run and reports newly appeared ports and assets.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/state.h"
#include "sentinel/buf.h"
#include "sentinel/model.h"
#include "sentinel/paths.h"
#include "sentinel/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Build the set of "target|type|value" keys present in a findings array,
 * remembering which finding index each key came from. */
static void collect_keys(const json_value_t *findings, char ***keys, size_t **idx,
                         size_t *count)
{
    *keys = NULL;
    *idx = NULL;
    *count = 0;
    size_t cap = 0;
    for (size_t i = 0; i < json_len(findings); i++) {
        const json_value_t *f = json_at(findings, i);
        const char *target = json_get_str(f, "target");
        const char *ftype  = json_get_str(f, "finding_type");
        const char *value  = json_get_str(f, "value");
        const char *t = target ? target : "local";
        const char *ty = ftype ? ftype : "";
        const char *v = value ? value : "";
        size_t n = strlen(t) + strlen(ty) + strlen(v) + 4;
        char *k = malloc(n);
        if (!k) continue;
        snprintf(k, n, "%s|%s|%s", t, ty, v);
        if (*count == cap) {
            cap = cap ? cap * 2 : 32;
            char **nk = realloc(*keys, cap * sizeof(char *));
            if (!nk) { free(k); continue; }
            *keys = nk;
            size_t *ni = realloc(*idx, cap * sizeof(size_t));
            if (!ni) { free(k); continue; }
            *idx = ni;
        }
        (*keys)[*count] = k;
        (*idx)[*count] = i;
        (*count)++;
    }
}

static int has_key(char **keys, size_t count, const char *k)
{
    for (size_t i = 0; i < count; i++)
        if (strcmp(keys[i], k) == 0) return 1;
    return 0;
}

json_value_t *state_diff(const json_value_t *current)
{
    json_value_t *drift = json_array();
    if (!drift) return NULL;

    if (paths_ensure_dir() != 0) return drift;   /* no baseline yet */

    size_t prev_len = 0;
    char *prev_raw = read_file(paths_state_path("state.json"), &prev_len);
    if (!prev_raw) return drift;                 /* first run: nothing to diff */

    json_value_t *prev = json_parse(prev_raw, prev_len);
    free(prev_raw);
    if (!prev) return drift;

    /* Each declarator needs its own full pointer type: in `char **a, *b;` the
     * second name would be a plain char*, not char**. */
    char **cur_keys = NULL;
    char **old_keys = NULL;
    size_t *cur_idx_store = NULL;
    size_t *old_idx_store = NULL;
    size_t ncur = 0, nold = 0;
    collect_keys(current, &cur_keys, &cur_idx_store, &ncur);
    collect_keys(prev, &old_keys, &old_idx_store, &nold);
    const size_t *cur_idx = cur_idx_store;

    for (size_t i = 0; i < ncur; i++) {
        if (has_key(old_keys, nold, cur_keys[i])) continue;

        /* Only surface new *assets*; a changed severity on an existing finding
         * is noise, matching the Python behaviour. */
        if (!strstr(cur_keys[i], "|port|") && !strstr(cur_keys[i], "|host|") &&
            !strstr(cur_keys[i], "|subdomain|") && !strstr(cur_keys[i], "|technology|"))
            continue;

        const json_value_t *f = json_at(current, cur_idx[i]);
        const char *target = json_get_str(f, "target");
        const char *ftype  = json_get_str(f, "finding_type");
        const char *value  = json_get_str(f, "value");

        buf_t d; buf_init(&d);
        buf_printf(&d, "New %s '%s' on %s was not present in the previous baseline.",
                   ftype ? ftype : "finding", value ? value : "",
                   target ? target : "local");
        finding_t *df = finding_new("state-drift", FT_NOTE, value ? value : cur_keys[i],
                                    target ? target : "local", SEV_MEDIUM);
        if (df) {
            finding_set_detail(df, d.data);
            json_array_push(drift, finding_to_json(df));
            finding_free(df);
        }
        buf_free(&d);
    }

    for (size_t i = 0; i < ncur; i++) free(cur_keys[i]);
    for (size_t i = 0; i < nold; i++) free(old_keys[i]);
    free(cur_keys);
    free(old_keys);
    free(cur_idx_store);
    free(old_idx_store);
    json_free(prev);
    return drift;
}

int state_update(const json_value_t *current)
{
    if (paths_ensure_dir() != 0) return -1;
    char *dump = json_dump(current, 2);
    if (!dump) return -1;
    int rc = write_file(paths_state_path("state.json"), dump, strlen(dump));
    free(dump);
    return rc;
}
