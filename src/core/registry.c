/* registry.c — the explicit plugin table.
 *
 * Python discovered plugins by walking the package with pkgutil. C has no
 * equivalent, so the table is spelled out. That is a net win: the set of active
 * modules is visible in one place rather than implied by the filesystem.
 *
 * The table is built at first use rather than as a static initializer: each
 * plugin_t lives in its own translation unit, and a static array of *copies*
 * would need constant initializers, which a `const` object from another file
 * is not.
 *
 * Names, stages, and `requires` values are byte-identical to the Python
 * implementations they replace.
 */
#include "sentinel/plugin.h"

#include <stdlib.h>
#include <string.h>

/* Provided by each ported module. */
extern const plugin_t canary_audit_plugin;
extern const plugin_t cert_audit_plugin;
extern const plugin_t crtsh_plugin;
extern const plugin_t fim_plugin;
extern const plugin_t honeyport_plugin;
extern const plugin_t host_harden_plugin;
extern const plugin_t http_probe_plugin;
extern const plugin_t httpx_plugin;
extern const plugin_t lan_scanner_plugin;
extern const plugin_t nuclei_plugin;
extern const plugin_t osv_correlate_plugin;
extern const plugin_t pkg_audit_plugin;
extern const plugin_t process_anomaly_plugin;
extern const plugin_t prowler_plugin;
extern const plugin_t sherlock_plugin;
extern const plugin_t sigma_plugin;
extern const plugin_t sqlmap_plugin;
extern const plugin_t subfinder_plugin;
extern const plugin_t threat_intel_plugin;

static plugin_t *g_registry = NULL;
static size_t g_count = 0;
static int g_built = 0;

static void build_registry(void)
{
    if (g_built) return;
    g_built = 1;

    /* Ordered by pipeline stage: the orchestrator walks stages in order, so
     * this fixes the within-stage order. */
    const plugin_t *order[] = {
        &http_probe_plugin, &crtsh_plugin, &subfinder_plugin, &httpx_plugin,
        &lan_scanner_plugin,
        &nuclei_plugin, &osv_correlate_plugin, &pkg_audit_plugin,
        &cert_audit_plugin, &sqlmap_plugin,
        &sherlock_plugin, &prowler_plugin,
        &host_harden_plugin, &process_anomaly_plugin, &honeyport_plugin,
        &canary_audit_plugin, &fim_plugin, &sigma_plugin,
        &threat_intel_plugin,
    };
    g_count = sizeof(order) / sizeof(order[0]);
    g_registry = (plugin_t *)malloc(sizeof(plugin_t) * g_count);
    if (!g_registry) { g_count = 0; return; }
    /* Copy the structs, not the pointers: `order` is an array of
     * `const plugin_t *`, so a memcpy of sizeof(plugin_t) * g_count would
     * overrun it. */
    for (size_t i = 0; i < g_count; i++) g_registry[i] = *order[i];
}

const plugin_t *sentinel_plugin_list(size_t *count)
{
    build_registry();
    if (count) *count = g_count;
    return g_registry;
}

const plugin_t *sentinel_plugin_find(const char *name)
{
    build_registry();
    if (!name) return NULL;
    for (size_t i = 0; i < g_count; i++)
        if (g_registry[i].name && strcmp(g_registry[i].name, name) == 0)
            return &g_registry[i];
    return NULL;
}
