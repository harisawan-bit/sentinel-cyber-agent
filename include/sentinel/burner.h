#ifndef SENTINEL_BURNER_H
#define SENTINEL_BURNER_H

#define BURNER_LOG_NAME "burner_traps.json"

/* Render the hardened docker-compose blueprint for an isolated burner sandbox.
 * Caller frees. */
char *burner_compose_yaml(int ssh_port, int smtp_port, int n8n_port,
                          const char *memory_limit, const char *cpu_limit);

/* Run the decoy service trap until interrupted, or for `max_seconds` when > 0.
 * Single process, select() over three listeners. Returns 0 on clean exit. */
int burner_run(const char *host, int ssh_port, int smtp_port, int n8n_port,
               int max_seconds);

#endif /* SENTINEL_BURNER_H */
