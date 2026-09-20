"""Lightweight Telegram and Slack notifiers for homelab security alerts.

Zero third-party dependencies — uses standard library urllib.request.
"""
from __future__ import annotations
import json
import urllib.request
from typing import List, Dict, Any


def format_digest(findings: List[Dict[str, Any]], title: str = "Homelab Security Report") -> str:
    total = len(findings)
    sev_counts: Dict[str, int] = {}
    ports: List[str] = []
    critical_or_high: List[str] = []

    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        ftype = f.get("finding_type")
        if ftype == "port":
            val = f.get("value", "")
            svc = (f.get("metadata") or {}).get("service", "")
            ports.append(f"{val} ({svc})" if svc else val)
        if sev in ("critical", "high"):
            critical_or_high.append(f"[{sev.upper()}] {f.get('target')}: {f.get('value')} - {f.get('detail', '')}")

    lines = [
        f"🛡️ *SENTINEL HOMELAB DIGEST* // {title}",
        f"📊 *Total Findings*: {total}",
        f"🔴 Critical: {sev_counts.get('critical', 0)} | 🟠 High: {sev_counts.get('high', 0)} | 🟡 Medium: {sev_counts.get('medium', 0)} | 🔵 Low: {sev_counts.get('low', 0)} | ⚪ Info: {sev_counts.get('info', 0)}",
    ]
    if ports:
        lines.append(f"\n🔌 *Open Ports ({len(ports)})*:\n• " + "\n• ".join(ports[:15]))
        if len(ports) > 15:
            lines.append(f"  ...and {len(ports) - 15} more")
    if critical_or_high:
        lines.append(f"\n🚨 *Alerts ({len(critical_or_high)})*:\n• " + "\n• ".join(critical_or_high[:8]))
    return "\n".join(lines)


def send_telegram(token: str, chat_id: str, text: str) -> bool:
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"[!] Telegram notification failed: {e}")
        return False


def send_slack(webhook_url: str, text: str) -> bool:
    try:
        data = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(webhook_url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"[!] Slack notification failed: {e}")
        return False
