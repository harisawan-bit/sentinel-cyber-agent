/* registry_stub.c — empty plugin table for tools that never run the pipeline
 * (installer, bench). Linking the real registry would pull in all 19 plugins
 * for no benefit. */
#include "sentinel/plugin.h"
const plugin_t *sentinel_plugin_list(size_t *count){ if(count) *count=0; return 0; }
const plugin_t *sentinel_plugin_find(const char *n){ (void)n; return 0; }
