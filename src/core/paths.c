/* paths.c — runtime state directory resolution.
 *
 * The Python version resolved paths at import time, which meant SENTINEL_HOME
 * had to be set before import and could not be changed per-test. Here every
 * lookup re-reads the environment, so tests can relocate state at will.
 */
#include "sentinel/paths.h"
#include "sentinel/buf.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

const char *paths_state_dir(void)
{
    /* Re-read the environment on every call rather than caching. The cache
     * made SENTINEL_HOME effectively read once per process, so a test that
     * relocated state after the first call silently kept writing to the old
     * directory — which is how test data once landed in the real ~/.sentinel.
     * The value is built into a rotating pair of buffers to avoid a malloc
     * and a leak on every call. */
    static char bufs[2][1024];
    static int which = 0;
    char *out = bufs[which];
    which = !which;

    const char *env = getenv("SENTINEL_HOME");
    if (env && *env) {
        snprintf(out, sizeof(bufs[0]), "%s", env);
    } else {
        const char *home = getenv("HOME");
        if (!home || !*home) home = "/tmp";
        snprintf(out, sizeof(bufs[0]), "%s/.sentinel", home);
    }
    return out;
}

const char *paths_state_path(const char *name)
{
    static char bufs[2][2048];
    static int which = 0;
    char *out = bufs[which];
    which = !which;
    snprintf(out, sizeof(bufs[0]), "%s/%s", paths_state_dir(), name ? name : "");
    return out;
}

int paths_ensure_dir(void)
{
    const char *dir = paths_state_dir();
    if (!dir || !*dir) return -1;

    /* mkdir -p: create each missing component. */
    char *copy = sstrdup(dir);
    if (!copy) return -1;
    size_t len = strlen(copy);
    if (len && copy[len - 1] == '/') copy[len - 1] = '\0';

    for (char *p = copy + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(copy, 0700) != 0 && errno != EEXIST) { free(copy); return -1; }
        *p = '/';
    }
    int rc = (mkdir(copy, 0700) != 0 && errno != EEXIST) ? -1 : 0;
    free(copy);
    return rc;
}
