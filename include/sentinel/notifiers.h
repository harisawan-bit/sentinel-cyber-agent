#ifndef SENTINEL_NOTIFIERS_H
#define SENTINEL_NOTIFIERS_H

#include "sentinel/orchestrator.h"

/* Human-readable digest of the accumulated findings. Caller frees. */
char *notifier_digest(const orchestrator_t *o, const char *title);

/* Both return 1 on a 2xx response, 0 otherwise. */
int notifier_send_telegram(const char *token, const char *chat_id, const char *text);
int notifier_send_slack(const char *webhook, const char *text);

#endif /* SENTINEL_NOTIFIERS_H */
