"""Command-line entry point."""
from __future__ import annotations
import argparse, json, os, sys
from .core.orchestrator import Orchestrator
from .core.report import render
from .core.state import diff_and_update_state
from .core.notifiers import format_digest, send_telegram, send_slack


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel — unified MIT-licensed cyber security agent",
    )
    ap.add_argument("targets", nargs="+", help="targets: domains, hostnames, IPs, CIDRs, or usernames")
    ap.add_argument("--stages", nargs="*", help="limit to stages: recon scan osint cloud")
    ap.add_argument("--json", action="store_true", help="emit raw JSON")
    ap.add_argument("--out", default=None, help="write findings JSON to file")
    ap.add_argument("--report", default=None, help="write autonomous HTML report to file")
    ap.add_argument("--diff", action="store_true", help="detect new ports and assets against historical baseline")
    ap.add_argument("--notify", action="store_true", help="dispatch Slack / Telegram notifications")
    ap.add_argument("--telegram-token", default=None, help="Telegram Bot token")
    ap.add_argument("--telegram-chat-id", default=None, help="Telegram Chat ID")
    ap.add_argument("--slack-webhook", default=None, help="Slack incoming webhook URL")
    args = ap.parse_args(argv)

    orch = Orchestrator()
    stages = set(args.stages) if args.stages else None
    findings = orch.run(args.targets, stages=stages)

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

    if args.report:
        html = render(findings, title=" · ".join(args.targets[:3]))
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(html)

    if args.notify:
        digest = format_digest(findings, title=" · ".join(args.targets[:3]))
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
