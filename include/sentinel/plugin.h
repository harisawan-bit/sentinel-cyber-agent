/* sentinel/plugin.h — the engine interface every scan module implements.
 *
 * Mirrors the Python Plugin ABC. A plugin appends findings to the context
 * rather than yielding them, since C99 has no generators.
 */
#ifndef SENTINEL_PLUGIN_H
#define SENTINEL_PLUGIN_H

#include "sentinel/model.h"

/* Pipeline order. Must stay in sync with the Python STAGE_ORDER. */
typedef enum {
    STAGE_RECON = 0,
    STAGE_SCAN,
    STAGE_OSINT,
    STAGE_CLOUD,
    STAGE_AUDIT,
    STAGE_INTEL,
    STAGE__COUNT
} stage_t;

const char *stage_str(stage_t s);
stage_t      stage_parse(const char *s);

struct orchestrator;

typedef struct plugin {
    const char  *name;
    const char  *description;
    stage_t      stage;
    /* External binaries this plugin shells out to. Enforced by the
     * orchestrator, which skips the plugin with a clear note when absent. */
    const char *requires[4];   /* NULL-terminated */

    /* Append findings to ctx->findings. Return 0 on success, non-zero to have
     * the orchestrator record a plugin error. */
    int (*run)(struct orchestrator *ctx, const char *target);
} plugin_t;

/* The registry. Kept explicit rather than discovered: C has no pkgutil, and an
 * explicit table lets the linker dead-strip engines you do not use. */
const plugin_t *sentinel_plugin_list(size_t *count);
const plugin_t *sentinel_plugin_find(const char *name);

#endif /* SENTINEL_PLUGIN_H */
