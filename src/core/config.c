/* config.c — engine binary location. */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/config.h"
#include "sentinel/buf.h"
#include "sentinel/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Overridable so tests and packagers can point at a different ./bin without
 * recompiling. */
static const char *bin_dir(void)
{
    const char *env = getenv("SENTINEL_BIN_DIR");
    if (env && *env) return env;
    return "bin";
}

const char *bin_path(const char *name)
{
    static char buf[512];
    if (!name || !*name) return name;

    snprintf(buf, sizeof(buf), "%s/%s", bin_dir(), name);
    if (file_exists(buf)) return buf;

    /* Windows executables carry an .exe suffix; accept it when present so the
     * same plugin table works on both platforms. */
    snprintf(buf, sizeof(buf), "%s/%s.exe", bin_dir(), name);
    if (file_exists(buf)) return buf;

    /* Not vendored: let execvp() search PATH. */
    snprintf(buf, sizeof(buf), "%s", name);
    return buf;
}

int bin_available(const char *name)
{
    if (!name || !*name) return 0;
    char cand[512];
    snprintf(cand, sizeof(cand), "%s/%s", bin_dir(), name);
    if (file_exists(cand)) return 1;
    snprintf(cand, sizeof(cand), "%s/%s.exe", bin_dir(), name);
    if (file_exists(cand)) return 1;

    /* Search PATH ourselves so a missing engine is detected before the plugin
     * runs, rather than surfacing as a 127 exit from execvp. */
    const char *path = getenv("PATH");
    if (!path || !*path) return 0;
    const char *p = path;
    while (*p) {
        const char *sep = strchr(p, ':');
        size_t seglen = sep ? (size_t)(sep - p) : strlen(p);
        if (seglen && seglen < 400) {
            char full[512];
            snprintf(full, sizeof(full), "%.*s/%s", (int)seglen, p, name);
            if (access(full, X_OK) == 0) return 1;
            snprintf(full, sizeof(full), "%.*s/%s.exe", (int)seglen, p, name);
            if (access(full, X_OK) == 0) return 1;
        }
        if (!sep) break;
        p = sep + 1;
    }
    return 0;
}
