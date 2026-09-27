/* daemon.c — continuous monitoring loop and systemd integration.
 *
 * Ported from sentinel/core/daemon.py. The loop only notifies on drift or on
 * critical/high findings, so a quiet host stays quiet.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/daemon.h"
#include "sentinel/buf.h"
#include "sentinel/notifiers.h"
#include "sentinel/orchestrator.h"
#include "sentinel/report.h"
#include "sentinel/state.h"
#include "sentinel/util.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Set by the signal handler so the loop can exit between cycles instead of
 * being killed mid-write. */
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

char *daemon_systemd_unit(const char *exec_cmd, const char *user,
                          const char *group, const char *workdir)
{
    buf_t b; buf_init(&b);
    buf_printf(&b,
"[Unit]\n"
"Description=Sentinel Autonomous Cyber Security Guardian\n"
"Documentation=https://github.com/harisawan-bit/sentinel-cyber-agent\n"
"After=network.target network-online.target\n"
"Wants=network-online.target\n"
"\n"
"[Service]\n"
"Type=simple\n"
"User=%s\n"
"Group=%s\n"
"WorkingDirectory=%s\n"
"ExecStart=%s\n"
"Restart=always\n"
"RestartSec=15\n"
"\n"
"# The guardian is a listener, not a daemon that needs to write the host.\n"
"ProtectSystem=full\n"
"ProtectHome=read-only\n"
"NoNewPrivileges=true\n"
"PrivateTmp=true\n"
"StateDirectory=sentinel\n"
"\n"
"[Install]\n"
"WantedBy=multi-user.target\n",
        user && *user ? user : "root",
        group && *group ? group : "root",
        workdir && *workdir ? workdir : "/var/lib/sentinel",
        exec_cmd ? exec_cmd : "/usr/local/bin/sentinel --server-audit --daemon "
                              "--interval 300 --notify");
    return buf_release(&b);
}

int daemon_install_systemd(const char *unit, const char *service_name)
{
    char path[512];
    snprintf(path, sizeof(path), "/etc/systemd/system/%s", service_name);

    if (geteuid() != 0) {
        fprintf(stderr, "[!] root privileges are required to install a systemd service\n");
        return 1;
    }
    if (write_file(path, unit, strlen(unit)) != 0) {
        fprintf(stderr, "[!] could not write %s: %s\n", path, strerror(errno));
        return 1;
    }
    printf("[+] Wrote %s\n", path);

    /* argv arrays, never a shell string. */
    char *reload[] = { "systemctl", "daemon-reload", NULL };
    char *enable[] = { "systemctl", "enable", (char *)service_name, NULL };
    char *restart[] = { "systemctl", "restart", (char *)service_name, NULL };

    if (proc_run(reload, NULL, 0, 60) != 0) {
        fprintf(stderr, "[!] systemctl daemon-reload failed; run it manually\n");
        return 1;
    }
    if (proc_run(enable, NULL, 0, 60) != 0)
        fprintf(stderr, "[!] systemctl enable failed; enable it manually\n");
    if (proc_run(restart, NULL, 0, 60) != 0)
        fprintf(stderr, "[!] systemctl restart failed; start it manually\n");
    else
        printf("[+] %s enabled and running\n", service_name);
    return 0;
}

void daemon_run_loop(orchestrator_t *o, const char *const *targets,
                     int interval, unsigned stage_mask, const char *report_path,
                     const char *telegram_token, const char *telegram_chat_id,
                     const char *slack_webhook, int max_cycles)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    buf_t tlist; buf_init(&tlist);
    for (int i = 0; targets && targets[i] && i < 4; i++) {
        if (i) buf_puts(&tlist, ", ");
        buf_puts(&tlist, targets[i]);
    }

    printf("[*] Sentinel daemon started. Targets: %s | Interval: %ds\n",
           tlist.data, interval);
    printf("[*] Press Ctrl-C to stop.\n");
    fflush(stdout);

    int cycle = 0;
    while (!g_stop) {
        cycle++;
        double start = now_seconds();
        printf("[*] [Cycle %d] Running audit and scan pipeline...\n", cycle);
        fflush(stdout);

        /* Fresh orchestrator each cycle: findings must not accumulate, or the
         * notification digest would grow without bound. */
        orchestrator_t *work = orch_new();
        if (!work) break;
        work->server_audit = o ? o->server_audit : 0;
        orch_run(work, targets, stage_mask);

        json_value_t *findings = orch_findings_json(work);

        json_value_t *drift = state_diff(findings);
        size_t ndrift = json_len(drift);
        if (ndrift) {
            printf("[!] [Cycle %d] Detected %zu state drift event(s):\n", cycle, ndrift);
            for (size_t i = 0; i < ndrift; i++) {
                const char *d = json_get_str(json_at(drift, i), "detail");
                printf("    -> %s\n", d ? d : "(drift)");
            }
            for (size_t i = 0; i < ndrift; i++)
                json_array_push(findings, json_at(drift, i));
            drift->count = 0;   /* ownership moved into `findings` */
        }
        json_free(drift);
        state_update(findings);

        /* Alert on anything urgent, or anything the drift check flagged. */
        size_t alerts = 0;
        for (const finding_t *f = work->findings; f; f = f->next) {
            if (f->severity == SEV_CRITICAL || f->severity == SEV_HIGH ||
                f->type == FT_ANOMALY || f->type == FT_CANARY ||
                f->type == FT_VULNERABILITY)
                alerts++;
        }

        if (report_path) {
            char *html = report_render_json(findings, tlist.data);
            if (html) {
                if (write_file(report_path, html, strlen(html)) != 0)
                    printf("[!] Could not write the report to %s\n", report_path);
                free(html);
            }
        }

        if (ndrift || alerts) {
            buf_t title; buf_init(&title);
            buf_printf(&title, "ALERT [Cycle %d] %s", cycle, tlist.data);
            char *digest = notifier_digest(work, title.data);
            if (telegram_token && telegram_chat_id &&
                notifier_send_telegram(telegram_token, telegram_chat_id, digest))
                printf("[+] Telegram notification sent.\n");
            if (slack_webhook && notifier_send_slack(slack_webhook, digest))
                printf("[+] Slack notification sent.\n");
            free(digest);
            buf_free(&title);
        }

        double elapsed = now_seconds() - start;
        printf("[+] [Cycle %d] Finished in %.2fs. Findings: %zu (Alerts: %zu)\n",
               cycle, elapsed, json_len(findings), alerts);
        fflush(stdout);

        json_free(findings);
        orch_free(work);

        if (max_cycles > 0 && cycle >= max_cycles) break;
        if (g_stop) break;

        /* Sleep in short slices so a signal is acted on promptly rather than
         * after a full interval. */
        double sleep_left = (double)interval - elapsed;
        if (sleep_left < 1.0) sleep_left = 1.0;
        while (sleep_left > 0 && !g_stop) {
            double slice = sleep_left > 0.5 ? 0.5 : sleep_left;
            struct timespec ts = { (time_t)slice, (long)((slice - (time_t)slice) * 1e9) };
            nanosleep(&ts, NULL);
            sleep_left -= slice;
        }
    }

    printf("[*] Sentinel daemon stopped after %d cycle(s).\n", cycle);
    buf_free(&tlist);
}
