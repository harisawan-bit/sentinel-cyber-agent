/* sherlock.c — Username OSINT via the sherlock-project/sherlock Python module.
 *
 * Ported from sentinel/core/plugins/sherlock_plugin.py.
 *
 * sherlock is not a standalone binary: the Python plugin drove it as
 * `python -m sherlock_project.sherlock`. This port keeps that shape —
 * `python3 -m sherlock <handle> --print-found` — and requires[] advertises
 * python3 so the orchestrator skips the plugin with a clear note when there is
 * no interpreter.
 *
 * argv is passed as a vector to proc_capture(), never as a shell string, so a
 * hostile handle cannot be interpreted as syntax.
 */
#include "sentinel/sentinel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHERLOCK_TOOL   "sherlock"
#define SHERLOCK_TIMEOUT 300
/* Bound on how much of a subprocess line we echo back in a note. */
#define SHERLOCK_SNIPPET 160

/* HTML-escape for text that lands in a finding's `detail`/`value` (contract
 * hard rule 5). Metadata is JSON-serialized, so json_dump_to() escapes it. */
static char *esc_html(const char *s)
{
    buf_t b;
    buf_init(&b);
    for (const char *p = s ? s : ""; *p; p++) {
        switch (*p) {
            case '&': buf_puts(&b, "&amp;");  break;
            case '<': buf_puts(&b, "&lt;");   break;
            case '>': buf_puts(&b, "&gt;");   break;
            case '"': buf_puts(&b, "&quot;"); break;
            case '\'': buf_puts(&b, "&#39;"); break;
            default:  buf_putc(&b, *p);       break;
        }
    }
    return buf_release(&b);
}

static int is_url(const char *s)
{
    return strncmp(s, "https://", 8) == 0 || strncmp(s, "http://", 7) == 0;
}

/* sstrndup() copies n bytes unconditionally, so it over-reads a buffer shorter
 * than n. Snippet copies must clamp to the actual length first. */
static char *dup_prefix(const char *s, size_t n)
{
    size_t len = strlen(s);
    return sstrndup(s, len < n ? len : n);
}

/* Site name for a profile URL: strip scheme, trailing slash, and the path.
 * sherlock's --print-found emits bare profile URLs with no CSV columns, so the
 * host is the only site identity available (the Python version read `name`
 * and `http_status` out of its CSV). */
static char *host_of(const char *url)
{
    const char *p = url;
    if (strncmp(p, "https://", 8) == 0) p += 8;
    else if (strncmp(p, "http://", 7) == 0) p += 7;

    const char *end = p;
    while (*end && *end != '/' && *end != '?' && *end != '#') end++;

    char *host = sstrndup(p, (size_t)(end - p));
    if (host) str_lower(host, host, strlen(host) + 1);
    return host;
}

static void emit_account(orchestrator_t *ctx, const char *target, const char *url)
{
    char *esc_url = esc_html(url);
    char *host = host_of(url);

    finding_t *f = finding_new(SHERLOCK_TOOL, FT_ACCOUNT, esc_url, target, SEV_INFO);
    if (f) {
        char *esc_host = esc_html(host ? host : "");
        buf_t d;
        buf_init(&d);
        buf_printf(&d, "Username presence on %s (sherlock --print-found)", esc_host);
        finding_set_detail(f, d.data);
        buf_free(&d);
        free(esc_host);

        json_value_t *meta = json_object();
        json_object_set_str(meta, "site", host ? host : "");
        json_object_set_str(meta, "url", url);
        finding_set_meta(f, meta);
        orch_add(ctx, f);
    }
    free(esc_url);
    free(host);
}

static int run(orchestrator_t *ctx, const char *target)
{
    char *argv[] = { "python3", "-m", "sherlock", (char *)target, "--print-found", NULL };

    size_t out_len = 0;
    char *out = proc_capture(argv, &out_len, SHERLOCK_TIMEOUT);
    if (!out) {
        orch_note(ctx, SHERLOCK_TOOL, "error: sherlock could not be started", target,
                  "proc_capture() failed; install the sherlock Python module "
                  "(pip install sherlock-project) or skip the osint stage.");
        return 0;
    }

    size_t emitted = 0;
    /* proc_capture() merges stderr into stdout, so python's own diagnostics
     * ("No module named sherlock", tracebacks) arrive here too. Keeping only
     * well-formed URLs filters them out. Lines are walked in place rather than
     * with strtok_r: no global tokenizer state, no POSIX feature-test macro. */
    for (char *line = out; line && *line; ) {
        char *nl = strpbrk(line, "\r\n");
        char *next = NULL;
        if (nl) { *nl = '\0'; next = nl + 1; }

        str_trim(line);
        if (is_url(line)) {
            emit_account(ctx, target, line);
            emitted++;
        }
        line = next;
    }

    if (emitted == 0) {
        /* No URLs. Either the handle genuinely has no profiles or the module
         * is missing — surface the first line of output so the operator can
         * tell, rather than a silent empty run. */
        char *first = dup_prefix(out, SHERLOCK_SNIPPET);
        if (first) {
            str_trim(first);
            /* Collapse newlines: this is a single-line detail field. */
            for (char *p = first; *p; p++)
                if (*p == '\n' || *p == '\r') *p = ' ';
            char *esc = esc_html(first);

            buf_t v;
            buf_init(&v);
            buf_printf(&v, "sherlock: no profiles found for '%s'", esc);
            buf_t d;
            buf_init(&d);
            if (first[0])
                buf_printf(&d, "sherlock output: %s", esc);
            else
                buf_puts(&d, "sherlock produced no output for this handle.");
            orch_note(ctx, SHERLOCK_TOOL, v.data, target, d.data);
            buf_free(&v);
            buf_free(&d);
            free(esc);
            free(first);
        } else {
            orch_note(ctx, SHERLOCK_TOOL, "sherlock: no profiles found", target,
                      "sherlock produced no output for this handle.");
        }
    }

    free(out);
    return 0;
}

const plugin_t sherlock_plugin = {
    SHERLOCK_TOOL,
    "Username presence across sites (sherlock-project/sherlock, MIT)",
    STAGE_OSINT,
    { "python3", NULL },
    run
};
