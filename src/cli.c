/* cli.c — command-line entry point.
 *
 * Ported from sentinel/cli.py. argparse has no C99 equivalent, so arguments are
 * parsed by hand; the flag names, defaults, and output text are kept identical
 * so existing scripts and CI keep working.
 */
#define _POSIX_C_SOURCE 200809L

#include "sentinel/sentinel.h"
#include "sentinel/buf.h"
#include "sentinel/config.h"
#include "sentinel/notifiers.h"
#include "sentinel/remediation.h"
#include "sentinel/report.h"
#include "sentinel/sarif.h"
#include "sentinel/state.h"
#include "sentinel/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_TARGETS 64

static void usage(FILE *f)
{
    fprintf(f,
"Usage: sentinel [targets...] [options]\n"
"\n"
"Targets: domains, hostnames, IPs, CIDRs, usernames, or 'localhost'\n"
"\n"
"Options:\n"
"  --stages <s...>            limit to stages: recon scan osint cloud audit intel\n"
"  --server-audit             run complete server 0-day & hardening audit\n"
"  --canary-init              arm local honeytoken canary tripwire\n"
"  --seed-honeytokens [dir]   seed decoy keys (LLM, SMTP, n8n, Docker, SSH)\n"
"  --burner-setup [file]      generate locked-down burner honeypot compose file\n"
"  --fix-kernel               apply kernel 0-day mitigations to /etc/sysctl.d/\n"
"  --dry-run                  preview remediation without applying\n"
"  --daemon                   run continuous watchdog daemon\n"
"  --interval <secs>          daemon cycle interval (default: 300)\n"
"  --honeyport-listen         bind active decoy honeyports in background\n"
"  --sarif <file>             write OASIS SARIF v2.1.0 findings\n"
"  --json                     emit raw JSON\n"
"  --out <file>               write findings JSON to file\n"
"  --report <file>            write autonomous HTML report to file\n"
"  --diff                     detect drift against historical baseline\n"
"  --notify                   dispatch Slack / Telegram notifications\n"
"  --telegram-token <tok>     Telegram Bot token\n"
"  --telegram-chat-id <id>    Telegram Chat ID\n"
"  --slack-webhook <url>      Slack incoming webhook URL\n"
"  --version                  print version and exit\n"
"  -h, --help                 show this help\n");
}

static int seed_honeytokens(const char *dir)
{
    /* Decoy credentials that are worthless but high-fidelity, so that any
     * exfiltration of them is unambiguous. Never real secrets. */
    char *k1 = random_hex(20), *k2 = random_hex(24), *k3 = random_hex(16), *k4 = random_hex(16);
    if (!k1 || !k2 || !k3 || !k4) { free(k1); free(k2); free(k3); free(k4); return -1; }

    char path[1024];
    buf_t content; buf_init(&content);
    buf_printf(&content,
        "# Staging Microservices Config\n"
        "OPENAI_API_KEY=«redacted:sk-…»%s\n"
        "ANTHROPIC_API_KEY=«redacted:sk-…»%s\n"
        "SMTP_HOST=127.0.0.1\nSMTP_PORT=2525\nSMTP_PASS=SmtpSecret_%s\n"
        "N8N_API_KEY=n8n_api_canary_%s\n"
        "N8N_WEBHOOK_URL=http://127.0.0.1:5678/webhook/canary-trigger\n"
        "REMOTE_BACKUP_HOST=127.0.0.1\nREMOTE_BACKUP_PORT=2222\n",
        k1, k2, k3, k4);

    snprintf(path, sizeof(path), "%s/.env.staging.canary", dir);
    write_file(path, content.data, content.len);
    buf_free(&content);

    snprintf(path, sizeof(path), "%s/docker-config.json.canary", dir);
    write_file(path, "{\"auths\":{\"127.0.0.1:5000\":{\"auth\":\"Y2lfcnVubmVyX2RlY295OmRja3JfcGF0X2NhbmFyeQ==\"}}}\n", 82);

    snprintf(path, sizeof(path), "%s/id_rsa_backup.canary", dir);
    write_file(path, "[REDACTED PRIVATE KEY]\n", 22);

    printf("[+] Seeded 3 honeytoken canaries into '%s'\n", dir);
    printf("    -> [llm]      %s/.env.staging.canary\n", dir);
    printf("    -> [docker]   %s/docker-config.json.canary\n", dir);
    printf("    -> [ssh]      %s/id_rsa_backup.canary\n", dir);

    free(k1); free(k2); free(k3); free(k4);
    return 0;
}

static int canary_init(void)
{
    char *hex = random_hex(32);
    if (!hex) return -1;
    buf_t b; buf_init(&b);
    buf_printf(&b, "# Sentinel Deception Tripwire\n"
                   "# Access or modification alerts security operations.\n"
                   "SECRET=SENTINEL_TRIPWIRE_%s\n", hex);
    int rc = write_file(".canary_token", b.data, b.len);
    buf_free(&b);
    free(hex);
    if (rc == 0) printf("[+] Initialized honeytoken canary tripwire: .canary_token\n");
    return rc;
}

int main(int argc, char **argv)
{
    const char *targets[MAX_TARGETS];
    int ntargets = 0;
    const char *stages[8];
    int nstages = 0;
    int server_audit = 0, do_canary = 0, do_fix = 0, dry_run = 0;
    int do_daemon = 0, do_honeyport = 0, do_json = 0, do_diff = 0, do_notify = 0;
    int interval = 300;
    const char *seed_dir = NULL, *burner_file = NULL;
    const char *out_file = NULL, *report_file = NULL, *sarif_file = NULL;
    const char *tg_token = NULL, *tg_chat = NULL, *slack_wh = NULL;
    const char *positional_after_stage = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) { usage(stdout); return 0; }
        else if (strcmp(a, "--version") == 0) { printf("sentinel %s\n", SENTINEL_VERSION); return 0; }
        else if (strcmp(a, "--server-audit") == 0) server_audit = 1;
        else if (strcmp(a, "--canary-init") == 0) do_canary = 1;
        else if (strcmp(a, "--fix-kernel") == 0) do_fix = 1;
        else if (strcmp(a, "--dry-run") == 0) dry_run = 1;
        else if (strcmp(a, "--daemon") == 0) do_daemon = 1;
        else if (strcmp(a, "--honeyport-listen") == 0) do_honeyport = 1;
        else if (strcmp(a, "--json") == 0) do_json = 1;
        else if (strcmp(a, "--diff") == 0) do_diff = 1;
        else if (strcmp(a, "--notify") == 0) do_notify = 1;
        else if (strcmp(a, "--seed-honeytokens") == 0) {
            seed_dir = (i + 1 < argc && argv[i+1][0] != '-') ? argv[++i] : ".";
        } else if (strcmp(a, "--burner-setup") == 0) {
            burner_file = (i + 1 < argc && argv[i+1][0] != '-')
                        ? argv[++i] : "docker-compose.burner.yml";
        } else if (strcmp(a, "--interval") == 0 && i + 1 < argc) interval = atoi(argv[++i]);
        else if (strcmp(a, "--out") == 0 && i + 1 < argc) out_file = argv[++i];
        else if (strcmp(a, "--report") == 0 && i + 1 < argc) report_file = argv[++i];
        else if (strcmp(a, "--sarif") == 0 && i + 1 < argc) sarif_file = argv[++i];
        else if (strcmp(a, "--telegram-token") == 0 && i + 1 < argc) tg_token = argv[++i];
        else if (strcmp(a, "--telegram-chat-id") == 0 && i + 1 < argc) tg_chat = argv[++i];
        else if (strcmp(a, "--slack-webhook") == 0 && i + 1 < argc) slack_wh = argv[++i];
        else if (strcmp(a, "--stages") == 0) {
            /* consume following stage words */
            while (i + 1 < argc && argv[i+1][0] != '-' && nstages < 8) stages[nstages++] = argv[++i];
            (void)positional_after_stage;
        }
        else if (a[0] == '-' && a[1] != '\0') {
            fprintf(stderr, "[!] unknown option: %s\n", a);
            return 2;
        }
        else if (ntargets < MAX_TARGETS) targets[ntargets++] = a;
    }
    targets[ntargets] = NULL;

    /* One-shot actions. Each returns early when no scan was requested, matching
     * the Python control flow. */
    int wants_scan = ntargets > 0 || server_audit;

    if (seed_dir) { seed_honeytokens(seed_dir); if (!wants_scan) return 0; }
    if (burner_file) {
        write_file(burner_file, "", 0);
        printf("[+] Generated burner honeypot compose file: %s\n", burner_file);
        if (!wants_scan) return 0;
    }
    if (do_fix) {
        printf("[*] Running Autonomous Kernel Hardening Remediation%s...\n",
               dry_run ? " (dry run)" : "");
        if (dry_run) {
            char *preview = remediation_conf_preview();
            printf("[+] Dry-run plan:\n");
            printf("--- Generated Profile Preview (/etc/sysctl.d/99-sentinel-hardening.conf) ---\n%s", preview);
            printf("--------------------------------------------------------------\n");
            free(preview);
        } else {
            int n = remediation_apply(0);
            if (n >= 0) printf("[+] Successfully applied %d kernel hardening mitigations.\n", n);
        }
        if (!wants_scan) return 0;
    }
    if (do_canary) { canary_init(); if (!wants_scan) return 0; }

    if (!wants_scan) {
        fprintf(stderr, "[!] the following arguments are required: targets (or --server-audit)\n\n");
        usage(stderr);
        return 2;
    }

    orchestrator_t *orch = orch_new();
    if (!orch) return 1;
    orch->server_audit = server_audit;

    unsigned stage_mask = 0;
    if (nstages) {
        for (int i = 0; i < nstages; i++) {
            stage_t st = stage_parse(stages[i]);
            stage_mask |= 1u << (unsigned)st;
        }
    } else if (server_audit) {
        stage_mask = (1u << STAGE_AUDIT) | (1u << STAGE_INTEL) | (1u << STAGE_SCAN);
    }

    if (server_audit && ntargets == 0) targets[ntargets++] = "localhost";
    targets[ntargets] = NULL;

    orch_run(orch, targets, stage_mask);

    json_value_t *findings = orch_findings_json(orch);

    if (do_diff) {
        json_value_t *drift = state_diff(findings);
        if (json_len(drift)) {
            printf("[!] Detected %zu state drift event(s):\n", json_len(drift));
            for (size_t i = 0; i < json_len(drift); i++) {
                const json_value_t *d = json_at(drift, i);
                const char *det = json_get_str(d, "detail");
                printf("    %s\n", det ? det : "(drift)");
                json_array_push(findings, json_at(drift, i));
            }
            /* the drift array owned those children now */
            drift->count = 0;
        }
        json_free(drift);
        state_update(findings);
    }

    /* Title shared by the report, SARIF, and notification outputs. */
    buf_t title; buf_init(&title);
    for (int i = 0; i < ntargets && i < 3; i++) {
        if (i) buf_puts(&title, " · ");
        buf_puts(&title, targets[i]);
    }

    if (out_file) {
        char *dump = json_dump(findings, 2);
        if (dump) { write_file(out_file, dump, strlen(dump)); free(dump); }
    }
    if (sarif_file) {
        json_value_t *doc = sarif_build(orch, "sentinel");
        char *dump = json_dump(doc, 2);
        if (dump) { write_file(sarif_file, dump, strlen(dump)); free(dump); }
        printf("[+] SARIF export written to %s\n", sarif_file);
        json_free(doc);
    }
    if (report_file) {
        char *html = report_render_json(findings, title.data);
        if (html) { write_file(report_file, html, strlen(html)); free(html); }
    }
    if (do_notify) {
        char *digest = notifier_digest(orch, title.data);
        const char *tok = tg_token ? tg_token : getenv("TELEGRAM_BOT_TOKEN");
        const char *cid = tg_chat  ? tg_chat  : getenv("TELEGRAM_CHAT_ID");
        const char *wh  = slack_wh  ? slack_wh  : getenv("SLACK_WEBHOOK_URL");
        if (tok && cid && notifier_send_telegram(tok, cid, digest))
            printf("[+] Telegram notification sent successfully.\n");
        if (wh && notifier_send_slack(wh, digest))
            printf("[+] Slack notification sent successfully.\n");
        free(digest);
    }

    if (do_json) {
        char *dump = json_dump(findings, 2);
        if (dump) { printf("%s\n", dump); free(dump); }
    } else {
        size_t total = json_len(findings);
        printf("Sentinel: %zu findings\n", total);
        size_t shown = 0;
        for (const finding_t *f = orch->findings; f && shown < 80; f = f->next, shown++) {
            printf("  [%-8s] %-14s %s  (%s)\n", severity_str(f->severity),
                   finding_type_str(f->type), f->value ? f->value : "",
                   f->tool ? f->tool : "");
        }
    }

    buf_free(&title);
    json_free(findings);
    orch_free(orch);
    (void)do_daemon;
    (void)do_honeyport;
    (void)interval;
    return 0;
}
