#ifndef SENTINEL_CONFIG_H
#define SENTINEL_CONFIG_H

#include <stddef.h>

/* Locate an engine binary. Prefers ./bin/<name> (the vendored copy installed by
 * scripts/install_engines.py) and falls back to PATH resolution by the caller.
 * Returns `name` unchanged when neither exists, so it can be handed straight to
 * execvp(). Valid until the next call. */
const char *bin_path(const char *name);

/* Non-zero when `name` is resolvable (either ./bin/<name> or on PATH). */
int bin_available(const char *name);

typedef struct {
    int interval;
    const char *telegram_token;
    const char *telegram_chat_id;
    const char *slack_webhook;
    const char *discord_webhook;
    const char *report_path;
    const char *stages[8];
    size_t stage_count;
} sentinel_config_t;

void config_init(sentinel_config_t *config);
int config_load(sentinel_config_t *config, const char *path);
int config_save(const sentinel_config_t *config, const char *path);

#endif /* SENTINEL_CONFIG_H */
