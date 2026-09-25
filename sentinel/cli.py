"""Command-line entry point."""
from __future__ import annotations
import argparse, json, os, sys
from .core.orchestrator import Orchestrator
from .core.report import render
from .core.state import diff_and_update_state
from .core.notifiers import format_digest, send_telegram, send_slack
from .core.remediation import apply_remediation, plan_remediation
from .core.sarif import findings_to_sarif
from .core.daemon import run_daemon_loop, generate_systemd_unit, install_systemd_service
from .core.plugins.honeyport_plugin import HoneyportServer
from .core.deception import seed_all_honeytokens
from .core.honeypot_burner import generate_burner_docker_compose, MicroBurnerDaemon


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel — unified MIT-licensed cyber security agent",
    )
    ap.add_argument("targets", nargs="*", default=[], help="targets: domains, hostnames, IPs, CIDRs, usernames, or 'localhost'")
    ap.add_argument("--stages", nargs="*", help="limit to stages: recon scan osint cloud audit intel")
    ap.add_argument("--server-audit", action="store_true", help="run complete server 0-day & hardening audit (audit, intel, scan on localhost)")
    ap.add_argument("--canary-init", action="store_true", help="initialize and arm local honeytoken canary tripwire for 0-day detection")
    ap.add_argument("--seed-honeytokens", nargs="?", const=".", default=None, help="seed high-fidelity decoy keys (LLM, SMTP, n8n, Docker, SSH) into target dir")
    ap.add_argument("--burner-setup", nargs="?", const="docker-compose.burner.yml", default=None, help="generate locked-down 32MB burner honeypot docker-compose file")
    ap.add_argument("--burner-daemon", action="store_true", help="start pure-Python micro-burner trap (<5MB RAM, SSH/SMTP/n8n) in background")
    ap.add_argument("--fix-kernel", action="store_true", help="autonomously apply kernel 0-day mitigations to /etc/sysctl.d/")
    ap.add_argument("--dry-run", action="store_true", help="preview remediation changes without applying")
    ap.add_argument("--daemon", action="store_true", help="run continuous background watchdog daemon")
    ap.add_argument("--interval", type=int, default=300, help="daemon cycle interval in seconds (default: 300)")
    ap.add_argument("--install-systemd", action="store_true", help="generate and install Linux systemd service")
    ap.add_argument("--sarif", default=None, help="write findings in OASIS SARIF v2.1.0 format to file")
    ap.add_argument("--honeyport-listen", action="store_true", help="bind active decoy honeyports in background")
    ap.add_argument("--json", action="store_true", help="emit raw JSON")
    ap.add_argument("--out", default=None, help="write findings JSON to file")
    ap.add_argument("--report", default=None, help="write autonomous HTML report to file")
    ap.add_argument("--diff", action="store_true", help="detect new ports and assets against historical baseline")
    ap.add_argument("--notify", action="store_true", help="dispatch Slack / Telegram notifications")
    ap.add_argument("--telegram-token", default=None, help="Telegram Bot token")
    ap.add_argument("--telegram-chat-id", default=None, help="Telegram Chat ID")
    ap.add_argument("--slack-webhook", default=None, help="Slack incoming webhook URL")
    args = ap.parse_args(argv)

    if args.seed_honeytokens is not None:
        target_dir = args.seed_honeytokens
        seeded = seed_all_honeytokens(target_dir=target_dir)
        print(f"[+] Successfully seeded {len(seeded)} honeytoken canaries into '{target_dir}':")
        for s in seeded:
            print(f"    -> [{s.get('category')}] {s.get('path')}")
        if not args.targets and not args.server_audit:
            return 0

    if args.burner_setup is not None:
        compose_content = generate_burner_docker_compose()
        with open(args.burner_setup, "w", encoding="utf-8") as f:
            f.write(compose_content)
        print(f"[+] Generated locked-down burner honeypot compose file: {args.burner_setup}")
        print("    -> Memory capped: 32MB | CPU limit: 0.05 | Network: Isolated Bridge")
        print("    -> Run with: docker compose -f " + args.burner_setup + " up -d")
        if not args.targets and not args.server_audit:
            return 0

    if args.burner_daemon:
        burner = MicroBurnerDaemon()
        burner.start()
        print("[+] Micro-burner honeypot daemon running in background (<5MB RAM).")
        print(f"    -> Traps active on ports: SSH={burner.ssh_port}, SMTP={burner.smtp_port}, n8n={burner.n8n_port}")
        if not args.targets and not args.server_audit:
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                burner.stop()
                return 0

    if args.fix_kernel:
        print("[*] Running Autonomous Kernel Hardening Remediation...")
        res = apply_remediation(dry_run=args.dry_run)
        if res.get("status") in ("dry_run", "unsupported_platform"):
            if res.get("status") == "unsupported_platform":
                print(f"[*] Platform '{res.get('platform')}' detected. Previewing Linux server hardening profile:")
            else:
                print("[+] Dry-run plan:")
            for p in res.get("planned_changes", []):
                print(f"    [MOD] {p['param']}: {p['current']} -> {p['target']} ({p['description']})")
            print(f"[+] Total compliant: {res.get('compliant_count')}/{res.get('total_checked')}")
            print("\n--- Generated Profile Preview (/etc/sysctl.d/99-sentinel-hardening.conf) ---")
            print(res.get("conf_preview", "").strip())
            print("------------------------------------------------------------------------------\n")
        elif res.get("status") == "applied":
            print(f"[+] Successfully applied {res.get('applied_count')} kernel hardening mitigations.")
            for param in res.get("applied_params", []):
                print(f"    [OK] {param}")
            if res.get("conf_path"):
                print(f"[+] Configuration written to {res.get('conf_path')}")
        else:
            print(f"[!] Remediation status: {res.get('status')} {res.get('error', '')}")
        if not args.targets and not args.server_audit:
            return 0

    if args.install_systemd:
        unit = generate_systemd_unit()
        if sys.platform.startswith("linux"):
            res = install_systemd_service(unit)
            print(f"[+] Systemd installation: {res}")
        else:
            print("[*] Generated systemd unit preview (Linux only):\n")
            print(unit)
        if not args.targets and not args.server_audit:
            return 0

    if args.canary_init:
        import hashlib
        canary_path = os.path.abspath(".canary_token")
        token_secret = "SENTINEL_TRIPWIRE_" + hashlib.sha256(os.urandom(32)).hexdigest()
        with open(canary_path, "w", encoding="utf-8") as f:
            f.write(f"# Sentinel Deception Tripwire\n# Access or modification alerts security operations.\nSECRET={token_secret}\n")
        print(f"[+] Initialized honeytoken canary tripwire: {canary_path}")
        if not args.targets and not args.server_audit:
            return 0

    orch = Orchestrator()
    targets = list(args.targets)
    stages = set(args.stages) if args.stages else None

    if args.server_audit:
        orch.server_audit = True
        if not targets:
            targets = ["localhost"]
        if stages is None:
            stages = {"audit", "intel", "scan"}

    if not targets:
        ap.error("the following arguments are required: targets (or specify --server-audit)")

    if args.honeyport_listen:
        server = HoneyportServer()
        server.start()
        print(f"[+] Active honeyport listeners started on ports {server.ports}")

    if args.daemon:
        tg_tok = args.telegram_token or os.environ.get("TELEGRAM_BOT_TOKEN")
        tg_cid = args.telegram_chat_id or os.environ.get("TELEGRAM_CHAT_ID")
        slack_wh = args.slack_webhook or os.environ.get("SLACK_WEBHOOK_URL")
        run_daemon_loop(
            orch=orch,
            targets=targets,
            interval=args.interval,
            stages=stages,
            report_path=args.report,
            telegram_token=tg_tok,
            telegram_chat_id=tg_cid,
            slack_webhook=slack_wh,
        )
        return 0

    findings = orch.run(targets, stages=stages)

    if args.diff:
        drift = diff_and_update_state(findings)
        if drift:
            print(f"[!] Detected {len(drift)} state drift event(s):")
            for d in drift:
                print(f"    {d.get('detail')}")
            findings.extend(drift)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)

    if args.sarif:
        sarif_doc = findings_to_sarif(findings, run_title=" · ".join(targets[:3]))
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(sarif_doc, fh, indent=2)
        print(f"[+] SARIF export written to {args.sarif}")

    if args.report:
        html = render(findings, title=" · ".join(targets[:3]))
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(html)

    if args.notify:
        digest = format_digest(findings, title=" · ".join(targets[:3]))
        tg_tok = args.telegram_token or os.environ.get("TELEGRAM_BOT_TOKEN")
        tg_cid = args.telegram_chat_id or os.environ.get("TELEGRAM_CHAT_ID")
        slack_wh = args.slack_webhook or os.environ.get("SLACK_WEBHOOK_URL")

        if tg_tok and tg_cid:
            if send_telegram(tg_tok, tg_cid, digest):
                print("[+] Telegram notification sent successfully.")
        if slack_wh:
            if send_slack(slack_wh, digest):
                print("[+] Slack notification sent successfully.")

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print(f"Sentinel: {len(findings)} findings")
        for f in findings[:80]:
            print(f"  [{f['severity']:<8}] {f['finding_type']:<14} {f['value']}  ({f['tool']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
