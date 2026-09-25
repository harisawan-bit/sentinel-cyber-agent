"""Sentinel Continuous Daemon and Systemd Integration Service.

Transforms Sentinel into an autonomous 24/7 server security guardian:
1. Low-footprint continuous polling loop (~15-25MB RAM).
2. Automatic state-drift detection (only alerts on new ports, anomalies, or 0-day tripwires).
3. Linux systemd service generator and installer.
"""
from __future__ import annotations
import os, sys, time, shutil, subprocess
from typing import Dict, List, Any, Optional
from .state import diff_and_update_state
from .notifiers import format_digest, send_telegram, send_slack
from .report import render

SYSTEMD_UNIT_TEMPLATE = """[Unit]
Description=Sentinel Autonomous Cyber Security Guardian
Documentation=https://github.com/harisawan-bit/sentinel-cyber-agent
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={group}
WorkingDirectory={workdir}
ExecStart={exec_cmd}
Restart=always
RestartSec=15
ProtectSystem=full
ProtectHome=read-only
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""


def generate_systemd_unit(
    exec_cmd: Optional[str] = None,
    user: str = "root",
    group: str = "root",
    workdir: str = "/var/lib/sentinel"
) -> str:
    """Generate systemd service file content."""
    if not exec_cmd:
        py_exe = sys.executable
        exec_cmd = f"{py_exe} -m sentinel.cli --server-audit --daemon --interval 300 --notify"

    return SYSTEMD_UNIT_TEMPLATE.format(
        user=user,
        group=group,
        workdir=workdir,
        exec_cmd=exec_cmd,
    )


def install_systemd_service(unit_content: str, service_name: str = "sentinel.service") -> Dict[str, Any]:
    """Install and enable systemd service on Linux."""
    if not sys.platform.startswith("linux"):
        return {"status": "unsupported", "error": "systemd is only supported on Linux"}

    target_path = f"/etc/systemd/system/{service_name}"
    try:
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(unit_content)

        subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
        subprocess.run(["systemctl", "enable", service_name], check=True, capture_output=True)
        subprocess.run(["systemctl", "restart", service_name], check=True, capture_output=True)
        return {"status": "installed", "path": target_path, "service": service_name}
    except PermissionError:
        return {"status": "permission_denied", "error": "Root privileges required to install systemd services"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def run_daemon_loop(
    orch,
    targets: List[str],
    interval: int = 300,
    stages: Optional[set] = None,
    report_path: Optional[str] = None,
    telegram_token: Optional[str] = None,
    telegram_chat_id: Optional[str] = None,
    slack_webhook: Optional[str] = None,
    max_cycles: Optional[int] = None,  # for unit tests
) -> None:
    """Run continuous background monitoring loop."""
    print(f"[*] Sentinel daemon started. Targets: {targets} | Interval: {interval}s")
    cycle = 0

    while True:
        cycle += 1
        start_t = time.time()
        print(f"[*] [Cycle {cycle}] Running audit and scan pipeline...")
        findings = orch.run(targets, stages=stages)

        # Baseline drift detection
        drift = diff_and_update_state(findings)
        if drift:
            print(f"[!] [Cycle {cycle}] Detected {len(drift)} state drift event(s):")
            for d in drift:
                print(f"    -> {d.get('detail')}")
            findings.extend(drift)

        # Critical / High findings filter for notification
        alerts = [
            f for f in findings
            if f.get("severity") in ("critical", "high")
            or f.get("finding_type") in ("anomaly", "canary", "vulnerability")
        ]

        if report_path:
            try:
                html = render(findings, title=" · ".join(targets[:3]))
                with open(report_path, "w", encoding="utf-8") as fh:
                    fh.write(html)
            except Exception as e:
                print(f"[!] Failed to write report: {e}")

        # Dispatch notifications if drift or critical alert occurred
        if drift or alerts:
            digest = format_digest(findings, title=f"ALERT [Cycle {cycle}] {' · '.join(targets[:2])}")
            if telegram_token and telegram_chat_id:
                send_telegram(telegram_token, telegram_chat_id, digest)
            if slack_webhook:
                send_slack(slack_webhook, digest)

        elapsed = time.time() - start_t
        print(f"[+] [Cycle {cycle}] Finished in {elapsed:.2f}s. Findings: {len(findings)} (Alerts: {len(alerts)})")

        if max_cycles and cycle >= max_cycles:
            break

        sleep_time = max(1.0, interval - elapsed)
        time.sleep(sleep_time)
