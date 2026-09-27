/* sentinel/paths.h — centralized runtime state locations.
 *
 * Every subsystem that persists state resolves it here so SENTINEL_HOME can
 * relocate it. The Python implementation resolved paths at import time, which
 * made the override untestable; here resolution is a call, so the environment
 * is read fresh every time.
 */
#ifndef SENTINEL_PATHS_H
#define SENTINEL_PATHS_H

/* SENTINEL_HOME if set (expanded, absolute), else ~/.sentinel. */
const char *paths_state_dir(void);

/* Absolute path to `name` inside the state dir. Valid until the next call. */
const char *paths_state_path(const char *name);

/* mkdir -p the state dir with mode 0700. Returns 0 on success. */
int  paths_ensure_dir(void);

#endif /* SENTINEL_PATHS_H */
