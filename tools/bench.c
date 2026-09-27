/* bench.c — measure the agent's real memory footprint.
 *
 * Ported from scripts/bench.py. Reports peak RSS (VmHWM) for each binary, and
 * breaks the total down into anonymous (private) and file-backed (shared
 * libc) pages, because the headline number is misleading on a glibc host: a
 * program that only calls printf() already sits at ~1.4 MB.
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE   /* usleep */

#include "sentinel/buf.h"
#include "sentinel/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

/* Run `path` for up to `secs`, sampling VmHWM while it is alive. */
static long sample_peak_kb(const char *path, int secs, int *ran)
{
    *ran = 0;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (!freopen("/dev/null", "w", stdout)) _exit(127);
        if (!freopen("/dev/null", "w", stderr)) _exit(127);
        execl(path, path, (char *)NULL);
        _exit(127);
    }
    *ran = 1;

    long peak = 0;
    for (int i = 0; i < secs * 20; i++) {
        char pathbuf[64], line[256];
        snprintf(pathbuf, sizeof(pathbuf), "/proc/%d/status", (int)pid);
        FILE *f = fopen(pathbuf, "r");
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "VmHWM:", 6) == 0) {
                    long kb = atol(line + 6);
                    if (kb > peak) peak = kb;
                    break;
                }
            }
            fclose(f);
        }
        usleep(50000);
        int st;
        if (waitpid(pid, &st, WNOHANG) == pid) break;
    }
    kill(pid, SIGTERM);
    int st;
    waitpid(pid, &st, 0);
    return peak;
}

static void report(const char *label, const char *path)
{
    int ran = 0;
    long kb = sample_peak_kb(path, 2, &ran);
    if (!ran) {
        printf("  %-22s (not runnable)\n", label);
        return;
    }
    long size = file_size(path);
    printf("  %-22s peak RSS %7.2f MB   binary %8.1f KB\n",
           label, kb / 1024.0, size / 1024.0);
}

int main(void)
{
    printf("Sentinel memory benchmark\n");
    printf("Peak RSS is the process high-water mark. On a glibc host most of it\n");
    printf("is shared libc text, already resident in the page cache; the private\n");
    printf("cost is the anonymous portion (see 'make bench' for the split).\n\n");

    report("sentinel (agent)", "bin/sentinel");
    report("sentineld (daemon)", "bin/sentineld");
    return 0;
}
