# C99 port contract — read fully before writing any file

Target: `sentinel-cyber-agent`, porting the Python agent to C99. Zero third-party
runtime deps except OpenSSL (link-time only, for TLS). Build is
`gcc -O2 -Wall -Wextra -Werror -std=c99 -Iinclude`. **No GNU extensions.**

## Headers you must use (already written, do not modify)

`include/sentinel/sentinel.h` is the umbrella. The individual headers:

```c
#include "sentinel/buf.h"        /* buf_t, sstrdup, str_trim, str_contains,
                                    str_ieq, str_lower, str_replace_all   */
#include "sentinel/json.h"       /* json_value_t and friends, json_escape   */
#include "sentinel/model.h"      /* finding_t, severity_t, finding_type_t  */
#include "sentinel/plugin.h"     /* plugin_t, stage_t                      */
#include "sentinel/orchestrator.h"/* orchestrator_t, orch_add, orch_note  */
#include "sentinel/paths.h"      /* paths_state_path(), paths_ensure_dir() */
#include "sentinel/util.h"       /* sha256_hex, http_do, proc_capture, ... */
```

Key signatures you will use constantly:

```c
/* util.h */
void  sha256_hex(const void *data, size_t len, char *out /* >=65 bytes */);
char *sha256_file_hex(const char *path);
char *random_hex(size_t nbytes);
double now_seconds(void);
void  iso8601(double t, char *out, size_t outlen);
char *read_file(const char *path, size_t *len);   /* malloc'd, NUL-terminated */
int   write_file(const char *path, const char *data, size_t len);
int   file_exists(const char *path);
long  file_size(const char *path);
char *read_sysctl(const char *path);
int   resolve_ipv4(const char *host, char *out, size_t outlen);
int   tcp_connect(const char *host, int port, int timeout_sec);
/* HTTP with TLS. Returns 0 on success, -1 transport fail, -2 TLS handshake fail.
   verify=1 validates the chain. Follows no redirects. */
int   http_do(const char *host, int port, const char *path, int use_tls,
              int verify, int timeout_sec, http_resp *out);
void  http_resp_free(http_resp *r);
char *url_encode(const char *s);
char *proc_capture(char *const argv[], size_t *out_len, int timeout_sec);
int   proc_run(char *const argv[], char *out, size_t out_len, int timeout_sec);
```

```c
/* model.h — Finding construction */
finding_t *finding_new(const char *tool, finding_type_t type, const char *value,
                       const char *target, severity_t sev);
void finding_set_detail(finding_t *f, const char *detail);
void finding_set_meta(finding_t *f, json_value_t *meta);  /* takes ownership */
const char *severity_str(severity_t s);
severity_t  severity_parse(const char *s);
```

Severity enum: `SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL, SEV_UNKNOWN`
Finding types: `FT_SUBDOMAIN FT_HOST FT_PORT FT_TECHNOLOGY FT_VULNERABILITY
FT_MISCONFIGURATION FT_ACCOUNT FT_CLOUD_RESOURCE FT_HARDENING FT_ANOMALY
FT_THREAT_INTEL FT_CANARY FT_INTEGRITY FT_DECEPTION FT_REMEDIATION FT_NOTE`

```c
/* plugin.h — what every ported plugin must look like */
typedef struct plugin {
    const char  *name;
    const char  *description;
    stage_t      stage;
    const char *requires[4];        /* NULL-terminated, e.g. {"nuclei", NULL} */
    int (*run)(struct orchestrator *ctx, const char *target);
} plugin_t;
```
Stages: `STAGE_RECON STAGE_SCAN STAGE_OSINT STAGE_CLOUD STAGE_AUDIT STAGE_INTEL`

```c
/* orchestrator.h */
void orch_add(orchestrator_t *o, finding_t *f);
void orch_note(orchestrator_t *o, const char *tool, const char *value,
               const char *target, const char *detail);
```

## The plugin file you write

Exactly this shape — a `static int run(...)` plus an exported
`const plugin_t <name>_plugin` that the central registry will reference:

```c
#include "sentinel/sentinel.h"
#include <string.h>

static int run(orchestrator_t *ctx, const char *target)
{
    /* ... */
    return 0;   /* non-zero is recorded by the orchestrator as a plugin error */
}

const plugin_t my_plugin = {
    "myplugin",                  /* must match the Python plugin name exactly */
    "One-line description.",
    STAGE_AUDIT,
    { NULL },                    /* required external binaries */
    run
};
```

## Hard rules

1. **C99 only.** No `strcasestr`, no `getline`, no `asprintf`, no
   `open_memstream`, no statement macros, no `typeof`. If you need something
   POSIX, `#define _POSIX_C_SOURCE 200809L` at the very top, before includes.
2. **No shell strings.** Never build a command into a string and pass it to a
   shell. Use `char *argv[] = {...}` + `execvp` (via `proc_capture`/`proc_run`)
   so nothing in attacker-controlled data can be interpreted.
3. **No global mutable state** between plugins. A plugin must be safe to run
   with a different target immediately after.
4. **Every plugin must degrade gracefully.** If a required binary is missing or
   a network call fails, emit an informational `FT_NOTE` finding (via
   `orch_note`) explaining what was skipped, and return 0. Never abort the run.
5. **Everything attacker-controlled gets escaped.** Any value from a network
   response, a file name, or a process cmdline must go through `json_escape`
   (for JSON) or HTML-escape it (for the report). Findings carry a `detail`
   string that lands in HTML — escape `& < > " '` at minimum.
6. **Comment the *why*, not the *what*.** These are ported from Python; a
   comment should explain non-obvious intent or a trap, not restate the code.
   Where behaviour is intentionally preserved from Python, say so and name the
   Python function.
7. **Free what you allocate.** Findings are freed by the orchestrator. Anything
   else you `malloc`/`sstrdup` you must `free`.
8. `size_t` vs `int`: be deliberate. Use `int` for ports and PIDs, `size_t` for
   buffer lengths.

## Porting fidelity

Port the Python logic **as it behaves**, not as it is written. If the Python
has a latent bug, do not reproduce it — fix it and note why in your summary.
Keep the emitted finding *values* and *severities* identical to Python so
report output stays comparable.

## Verify before you report done

Your code must compile warning-free, in isolation:

```sh
cd ~/.hermes/cache/scratch/sca
gcc -O2 -Wall -Wextra -Werror -std=c99 -Iinclude -c src/plugins/<file>.c -o /tmp/x.o
```

That must produce **zero output** and exit 0. If you cannot get it clean, you
have not finished. Do not report success on a file that emits warnings.
