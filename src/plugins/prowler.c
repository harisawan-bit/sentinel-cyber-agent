/* prowler.c — Cloud security posture via prowler-cloud/prowler.
 *
 * Ported from sentinel/core/plugins/prowler_plugin.py.
 *
 * Copyleft scanners stay GPL/AGPL-isolated: prowler is invoked as a separate
 * process and only its stdout is parsed, so its licence terms never reach the
 * MIT core. Nothing here is interpreted by a shell — argv goes straight to
 * execvp() via proc_capture().
 */
#include "sentinel/sentinel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROWLER_TOOL     "prowler"
#define PROWLER_TIMEOUT  600
/* Python matched the literal substring "FAIL" on the raw line and yielded
 * line.strip(); both behaviours are preserved exactly. */

/* HTML-escape for text that lands in a finding's `detail`/`value` (contract
 * hard rule 5). prowler output quotes resource ARNs and policy text, so this
 * is load-bearing, not decorative. */
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

/* sstrndup() copies n bytes unconditionally, so it over-reads a buffer shorter
 * than n. Snippet copies must clamp to the actual length first. */
static char *dup_prefix(const char *s, size_t n)
{
    size_t len = strlen(s);
    return sstrndup(s, len < n ? len : n);
}

static int run(orchestrator_t *ctx, const char *target)
{
    /* Python's guard was os.environ.get("AWS_ACCESS_KEY_ID") truthiness:
     * absent OR empty skips. Preserved — prowler without credentials spends
     * the full timeout failing to authenticate. */
    const char *key = getenv("AWS_ACCESS_KEY_ID");
    if (!key || !*key) {
        orch_note(ctx, PROWLER_TOOL,
                  "prowler skipped: no AWS credentials in environment", target,
                  "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (or a profile) "
                  "to run the cloud posture stage.");
        return 0;
    }

    char *argv[] = { "prowler", "aws", "--status", "FAIL", NULL };

    size_t out_len = 0;
    char *out = proc_capture(argv, &out_len, PROWLER_TIMEOUT);
    if (!out) {
        orch_note(ctx, PROWLER_TOOL, "error: prowler could not be started", target,
                  "proc_capture() failed; install prowler (pipx install prowler) "
                  "or skip the cloud stage.");
        return 0;
    }

    size_t emitted = 0;
    for (char *line = out; line && *line; ) {
        char *nl = strpbrk(line, "\r\n");
        char *next = NULL;
        if (nl) { *nl = '\0'; next = nl + 1; }

        /* Python checked `"FAIL" in line` on the untrimmed line. */
        if (strstr(line, "FAIL")) {
            char *trimmed = str_trim(line);
            char *esc = esc_html(trimmed);
            finding_t *f = finding_new(PROWLER_TOOL, FT_CLOUD_RESOURCE, esc,
                                       target, SEV_MEDIUM);
            if (f) {
                buf_t d;
                buf_init(&d);
                buf_printf(&d, "prowler aws check reported FAIL: %s", esc);
                finding_set_detail(f, d.data);
                buf_free(&d);
                orch_add(ctx, f);
            }
            free(esc);
            emitted++;
        }
        line = next;
    }

    if (emitted == 0) {
        char *head = dup_prefix(out, 160);
        char *esc = esc_html(head ? head : "");
        for (char *p = esc; *p; p++)
            if (*p == '\n' || *p == '\r') *p = ' ';
        buf_t v;
        buf_init(&v);
        buf_puts(&v, "prowler: no FAIL findings reported");
        buf_t d;
        buf_init(&d);
        if (head && head[0]) buf_printf(&d, "prowler output: %s", esc);
        else buf_puts(&d, "prowler produced no output.");
        orch_note(ctx, PROWLER_TOOL, v.data, target, d.data);
        buf_free(&v);
        buf_free(&d);
        free(esc);
        free(head);
    }

    free(out);
    return 0;
}

const plugin_t prowler_plugin = {
    PROWLER_TOOL,
    "AWS/GCP/Azure security posture (prowler-cloud/prowler, Apache-2.0)",
    STAGE_CLOUD,
    { "prowler", NULL },
    run
};

/* Copyleft engines (GPL/AGPL) are NOT linked here. They are invoked only as
 * isolated external subprocesses so their licence terms never reach the MIT
 * core. Same rationale as the Python module's closing comment. */
