/* burner.c — decoy service sandbox and honeytoken seeding.
 *
 * Ported from sentinel/core/honeypot_burner.py and sentinel/core/deception.py.
 *
 * The Python used one thread per listener. This uses a single select() loop
 * over three sockets, which keeps the trap inside one process with one address
 * space — the property that matters for something meant to sit resident on a
 * small host, and it removes the per-thread stacks the Python version paid for.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/burner.h"
#include "sentinel/buf.h"
#include "sentinel/json.h"
#include "sentinel/paths.h"
#include "sentinel/util.h"

#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* Set by the signal handler. A trap that ignores Ctrl-C is indistinguishable
 * from a hung process, which is exactly when you most need it to stop. */
static volatile sig_atomic_t g_burner_stop = 0;

static void on_burner_signal(int sig) { (void)sig; g_burner_stop = 1; }

/* ------------------------------------------------------------------ compose */

char *burner_compose_yaml(int ssh, int smtp, int n8n,
                          const char *mem, const char *cpu)
{
    buf_t b; buf_init(&b);
    /* Generated file, not user input: the ports are integers we formatted and
     * the limits come from our own defaults. */
    buf_printf(&b,
"# ====================================================================\n"
"# Sentinel Burner Honeypot Sandbox (Zero-Drain Isolation Machine)\n"
"# Capped at %s RAM, %s CPU, read-only rootfs, dropped capabilities.\n"
"# Diverts automated bots, rogue AI, and attackers away from host assets.\n"
"# ====================================================================\n"
"version: \"3.8\"\n"
"\n"
"services:\n"
"  sentinel-burner:\n"
"    image: alpine:latest\n"
"    container_name: sentinel-burner-sandbox\n"
"    hostname: internal-staging-worker\n"
"    restart: unless-stopped\n"
"    command: >\n"
"      sh -c \"echo 'Starting Sentinel Burner Trap...' &&\n"
"             nc -lk -p %d -e sh -c 'echo \\\"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\\\"; sleep 1' &\n"
"             nc -lk -p %d -e sh -c 'echo \\\"220 internal.smtp.relay ESMTP\\\"; sleep 1' &\n"
"             nc -lk -p %d -e sh -c 'echo \\\"HTTP/1.1 200 OK\\\"; sleep 1' &\n"
"             wait\"\n"
"    ports:\n"
"      - \"127.0.0.1:%d:%d\"\n"
"      - \"127.0.0.1:%d:%d\"\n"
"      - \"127.0.0.1:%d:%d\"\n"
"    read_only: true\n"
"    tmpfs:\n"
"      - /tmp:size=16M,noexec,nosuid,nodev\n"
"    cap_drop:\n"
"      - ALL\n"
"    security_opt:\n"
"      - no-new-privileges:true\n"
"    deploy:\n"
"      resources:\n"
"        limits:\n"
"          cpus: '%s'\n"
"          memory: %s\n"
"        reservations:\n"
"          cpus: '0.01'\n"
"          memory: 8m\n"
"    networks:\n"
"      - sentinel-burner-net\n"
"\n"
"networks:\n"
"  sentinel-burner-net:\n"
"    driver: bridge\n"
"    internal: false\n",
        mem, cpu, ssh, smtp, n8n, ssh, ssh, smtp, smtp, n8n, n8n, cpu, mem);
    return buf_release(&b);
}

/* ------------------------------------------------------------- trap logging */

/* Append one interaction to the burner log, keeping the last 100 entries.
 * Rewriting the whole file is acceptable at this size and keeps the format
 * identical to what the Python produced, so old logs still parse.
 */
static size_t g_burner_events = 0;

static void log_burner_event(const char *service, const char *remote_ip,
                             int remote_port, const char *payload)
{
    if (paths_ensure_dir() != 0) return;

    json_value_t *events = json_array();
    if (!events) return;

    size_t len = 0;
    char *raw = read_file(paths_state_path(BURNER_LOG_NAME), &len);
    if (raw) {
        json_value_t *prev = json_parse(raw, len);
        if (prev && prev->type == JSON_ARRAY) {
            for (size_t i = 0; i < json_len(prev); i++)
                json_array_push(events, json_at(prev, i));
        }
        /* The children now live in `events`; a recursive free would double-free
         * every one of them. */
        json_free_shallow(prev);
        free(raw);
    }

    /* Payload is attacker-controlled; cap it and drop non-printables so the
     * log stays readable and a control byte cannot corrupt a viewer. */
    char clean[201];
    size_t o = 0;
    for (size_t i = 0; payload && payload[i] && o < 200; i++) {
        unsigned char ch = (unsigned char)payload[i];
        if (ch < 0x20 || ch == 0x7f) { clean[o++] = '.'; }
        else clean[o++] = (char)ch;
    }
    clean[o] = '\0';

    json_value_t *e = json_object();
    json_object_set_str(e, "service", service);
    json_object_set_str(e, "remote_ip", remote_ip);
    json_object_set_num(e, "remote_port", remote_port);
    json_object_set_str(e, "payload", clean);
    json_object_set_num(e, "timestamp", now_seconds());
    json_array_push(events, e);

    /* Trim to the last 100. */
    while (json_len(events) > 100) {
        json_value_t *first = json_at(events, 0);
        for (size_t i = 1; i < json_len(events); i++) events->items[i-1] = events->items[i];
        events->count--;
        json_free(first);
    }

    char *dump = json_dump(events, 2);
    if (dump) { write_file(paths_state_path(BURNER_LOG_NAME), dump, strlen(dump)); free(dump); }
    json_free(events);
    g_burner_events++;
}

/* --------------------------------------------------------------- the daemon */

static int bind_trap(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host && *host ? host : "0.0.0.0", &a.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int burner_run(const char *host, int ssh_port, int smtp_port, int n8n_port,
               int max_seconds)
{
    int fds[3];
    const char *names[3] = { "SSH_DECOY", "SMTP_DECOY", "N8N_WEBHOOK_DECOY" };
    const char *banners[3] = {
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
        "220 mail.internal.corp ESMTP Sentinel-Burner Ready\r\n",
        NULL   /* the n8n decoy reads first, then replies */
    };
    int ports[3] = { ssh_port, smtp_port, n8n_port };

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_burner_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    g_burner_stop = 0;
    g_burner_events = 0;

    int armed = 0;
    for (int i = 0; i < 3; i++) {
        fds[i] = bind_trap(host, ports[i]);
        if (fds[i] >= 0) armed++;
        else fprintf(stderr, "[!] could not bind burner port %d: %s\n",
                     ports[i], strerror(errno));
    }
    if (!armed) {
        fprintf(stderr, "[!] no burner ports could be bound\n");
        return 1;
    }

    printf("[+] Micro-burner honeypot online (SSH=%d, SMTP=%d, n8n=%d).\n",
           ssh_port, smtp_port, n8n_port);
    printf("    -> %d trap socket(s) armed; logs to burner_traps.json\n", armed);
    fflush(stdout);

    double started = now_seconds();
    for (;;) {
        if (g_burner_stop) break;
        if (max_seconds > 0 && now_seconds() - started >= (double)max_seconds) break;

        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = 0;
        for (int i = 0; i < 3; i++) {
            if (fds[i] < 0) continue;
            FD_SET(fds[i], &rfds);
            if (fds[i] > maxfd) maxfd = fds[i];
        }
        struct timeval tv = { 1, 0 };
        int ready = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < 3; i++) {
            if (fds[i] < 0 || !FD_ISSET(fds[i], &rfds)) continue;

            struct sockaddr_in ca;
            socklen_t clen = sizeof(ca);
            int c = accept(fds[i], (struct sockaddr *)&ca, &clen);
            if (c < 0) continue;

            struct timeval ct = { 2, 0 };
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &ct, sizeof(ct));
            setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &ct, sizeof(ct));

            char ip[INET_ADDRSTRLEN] = "";
            inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));

            if (i == 2) {
                /* n8n webhook: read the payload, then acknowledge. */
                char buf[2048];
                ssize_t n = recv(c, buf, sizeof(buf) - 1, 0);
                if (n > 0) buf[n] = '\0'; else buf[0] = '\0';
                log_burner_event(names[i], ip, ntohs(ca.sin_port), buf);
                const char *resp =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: 42\r\n"
                    "Connection: close\r\n\r\n"
                    "{\"status\":\"received\",\"workflow\":\"queued\"}";
                send(c, resp, (int)strlen(resp), 0);
            } else {
                send(c, banners[i], (int)strlen(banners[i]), 0);
                char buf[1024];
                ssize_t n = recv(c, buf, sizeof(buf) - 1, 0);
                if (n > 0) buf[n] = '\0'; else buf[0] = '\0';
                log_burner_event(names[i], ip, ntohs(ca.sin_port), buf);
                if (i == 1) {
                    const char *rej = "503 5.5.1 Error: authentication failed\r\n";
                    send(c, rej, (int)strlen(rej), 0);
                }
            }
            close(c);
        }
    }

    for (int i = 0; i < 3; i++) if (fds[i] >= 0) close(fds[i]);
    printf("\n[*] Burner trap stopped after %zu interaction(s); see %s\n",
           g_burner_events, BURNER_LOG_NAME);
    return 0;
}
