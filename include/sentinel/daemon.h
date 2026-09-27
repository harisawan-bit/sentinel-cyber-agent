#ifndef SENTINEL_DAEMON_H
#define SENTINEL_DAEMON_H

#include "sentinel/orchestrator.h"

/* Render a hardened systemd unit. Caller frees. */
char *daemon_systemd_unit(const char *exec_cmd, const char *user,
                          const char *group, const char *workdir);

/* Write and enable the service. Returns 0 on success. */
int daemon_install_systemd(const char *unit, const char *service_name);

/* Run the monitoring loop until signalled, or for `max_cycles` when > 0. */
void daemon_run_loop(orchestrator_t *o, const char *const *targets,
                     int interval, unsigned stage_mask, const char *report_path,
                     const char *telegram_token, const char *telegram_chat_id,
                     const char *slack_webhook, int max_cycles);

#endif /* SENTINEL_DAEMON_H */
