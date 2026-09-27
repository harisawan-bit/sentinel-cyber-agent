/* notifiers.c — Slack and Telegram digests.
 *
 * Ported from sentinel/core/notifiers.py. Both transports are plain HTTPS POSTs
 * with a JSON body, so they share http_do() and the json writer.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/notifiers.h"
#include "sentinel/buf.h"
#include "sentinel/util.h"

#include <openssl/ssl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *notifier_digest(const orchestrator_t *o, const char *title)
{
    size_t counts[SEV_UNKNOWN + 1] = {0};
    size_t total = 0;
    for (const finding_t *f = o ? o->findings : NULL; f; f = f->next) {
        counts[f->severity]++;
        total++;
    }

    buf_t b; buf_init(&b);
    buf_printf(&b, "Sentinel: %zu finding(s)", total);
    if (title && *title) buf_printf(&b, " — %s", title);
    buf_puts(&b, "\n");
    buf_printf(&b, "CRITICAL %zu | HIGH %zu | MEDIUM %zu | LOW %zu | INFO %zu\n",
               counts[SEV_CRITICAL], counts[SEV_HIGH], counts[SEV_MEDIUM],
               counts[SEV_LOW], counts[SEV_INFO]);

    /* Surface the worst handful so a phone notification is actionable. */
    size_t shown = 0;
    for (const finding_t *f = o ? o->findings : NULL; f && shown < 10; f = f->next) {
        if (f->severity != SEV_CRITICAL && f->severity != SEV_HIGH) continue;
        buf_printf(&b, "- [%s] %s (%s)\n", severity_str(f->severity),
                   f->value ? f->value : "", f->tool ? f->tool : "");
        shown++;
    }
    return buf_release(&b);
}

/* Telegram's chat API needs the token in the URL path. */
int notifier_send_telegram(const char *token, const char *chat_id, const char *text)
{
    if (!token || !chat_id || !text) return 0;
    char host[128] = "api.telegram.org";
    char *enc = url_encode(text);

    /* Build the path: /bot<token>/sendMessage?chat_id=..&text=.. */
    buf_t path; buf_init(&path);
    buf_printf(&path, "/bot%s/sendMessage?chat_id=%s&text=%s",
               token, chat_id, enc ? enc : "");

    http_resp r;
    memset(&r, 0, sizeof(r));
    int rc = http_do(host, 443, path.data, 1, 1, 20, &r);
    int ok = (rc == 0 && r.status == 200);
    buf_free(&path);
    free(enc);
    http_resp_free(&r);
    return ok;
}

int notifier_send_slack(const char *webhook, const char *text)
{
    if (!webhook || !text) return 0;
    /* Webhooks are https://hooks.slack.com/services/... */
    if (strncmp(webhook, "https://", 8) != 0) return 0;

    char host[128] = "hooks.slack.com";
    const char *rest = strstr(webhook, "://");
    if (rest) {
        rest += 3;
        const char *slash = strchr(rest, '/');
        size_t hl = slash ? (size_t)(slash - rest) : strlen(rest);
        if (hl >= sizeof(host)) hl = sizeof(host) - 1;
        memcpy(host, rest, hl);
        host[hl] = '\0';
    }

    json_value_t *body = json_object();
    json_object_set_str(body, "text", text);
    char *payload = json_dump(body, 0);
    json_free(body);

    if (!payload) return 0;

    int fd = tcp_connect(host, 443, 20);
    if (fd < 0) { free(payload); return 0; }
    void *ssl = tls_connect(fd, host, 1, 20);
    if (!ssl) { close(fd); free(payload); return 0; }

    const char *path = strstr(webhook, host);
    if (path) path += strlen(host);

    size_t need = strlen(payload) + 512;
    char *req = malloc(need);
    if (!req) { tls_close(ssl, fd); free(payload); return 0; }

    snprintf(req, need,
             "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n"
             "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
             path ? path : "/", host, strlen(payload), payload);
    free(payload);

    SSL_write(ssl, req, (int)strlen(req));
    free(req);

    http_resp r;
    memset(&r, 0, sizeof(r));
    http_read_response(fd, ssl, &r);
    int ok = (r.status == 200);
    http_resp_free(&r);
    tls_close(ssl, fd);
    return ok;
}
