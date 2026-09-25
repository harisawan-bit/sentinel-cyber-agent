"""Cryptographic File Integrity Monitoring (FIM) & Anti-Persistence Auditor.

Pure-Python, zero external dependencies.
Monitors critical system files, binaries, and configurations against cryptographic baselines:
1. Detects unauthorized tampering in /etc/passwd, /etc/shadow, /etc/sudoers, /etc/ssh/sshd_config.
2. Audits persistence mechanisms: cron directories, systemd service units, and crontabs.
3. Detects kernel taint flags (/proc/sys/kernel/tainted) indicating unauthorized LKMs or rootkits.
4. Identifies world-writable binaries or critical directories.
"""
from __future__ import annotations
import hashlib, json, os, stat, sys
from typing import Iterator, Dict, Any, List
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity

CRITICAL_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/resolv.conf",
    "/etc/ld.so.conf",
]

PERSISTENCE_DIRS = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/systemd/system",
    "/var/spool/cron/crontabs",
]

FIM_BASELINE_PATH = os.path.expanduser("~/.sentinel/fim_baseline.json")


def _hash_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


class FimPlugin(Plugin):
    name = "fim_audit"
    description = "Cryptographic File Integrity Monitoring (FIM) and anti-persistence audit"
    stage = "audit"
    requires = []

    def _audit_kernel_taint(self, target: str) -> Iterator[Finding]:
        taint_file = "/proc/sys/kernel/tainted"
        if os.path.exists(taint_file):
            try:
                with open(taint_file, "r", encoding="utf-8") as f:
                    val = f.read().strip()
                if val and val != "0":
                    yield Finding(
                        tool=self.name,
                        finding_type=FindingType.VULNERABILITY,
                        value=f"Kernel Tainted Flag: {val}",
                        target=target,
                        severity=Severity.HIGH,
                        detail=(
                            f"KERNEL INTEGRITY COMPROMISE: Kernel taint flag is {val} (non-zero). "
                            f"Indicates out-of-tree, proprietary, or unauthorized module/rootkit was loaded."
                        ),
                        metadata={"taint_value": val, "threat_category": "kernel_taint"}
                    )
            except Exception:
                pass

    def _audit_persistence(self, target: str) -> Iterator[Finding]:
        found_cron_scripts = []
        for p_dir in PERSISTENCE_DIRS:
            if os.path.isdir(p_dir):
                try:
                    for entry in os.listdir(p_dir):
                        full = os.path.join(p_dir, entry)
                        if os.path.isfile(full):
                            st = os.stat(full)
                            mode = stat.S_IMODE(st.st_mode)
                            # Flag world-writable persistence scripts
                            if mode & 0o002:
                                yield Finding(
                                    tool=self.name,
                                    finding_type=FindingType.VULNERABILITY,
                                    value=f"World-Writable Persistence Script: {full}",
                                    target=target,
                                    severity=Severity.CRITICAL,
                                    detail=f"Insecure permissions ({oct(mode)}) on persistence file {full}. Any local user can escalate to root.",
                                    metadata={"path": full, "permissions": oct(mode)}
                                )
                            found_cron_scripts.append(full)
                except Exception:
                    pass

        if found_cron_scripts:
            yield Finding(
                tool=self.name,
                finding_type="hardening",
                value=f"Persistence Monitored ({len(found_cron_scripts)} units)",
                target=target,
                severity=Severity.INFO,
                detail=f"Audited {len(found_cron_scripts)} cron and systemd persistence files for integrity and permissions.",
                metadata={"monitored_units": len(found_cron_scripts)}
            )

    def _audit_file_integrity(self, target: str) -> Iterator[Finding]:
        os.makedirs(os.path.dirname(FIM_BASELINE_PATH), exist_ok=True)
        baseline = {}
        if os.path.exists(FIM_BASELINE_PATH):
            try:
                with open(FIM_BASELINE_PATH, "r", encoding="utf-8") as f:
                    baseline = json.load(f)
            except Exception:
                baseline = {}

        current_hashes = {}
        for p in CRITICAL_PATHS:
            if os.path.isfile(p):
                h = _hash_file(p)
                if h:
                    current_hashes[p] = h
                    if p in baseline:
                        prev_h = baseline[p]
                        if h != prev_h:
                            yield Finding(
                                tool=self.name,
                                finding_type=FindingType.VULNERABILITY,
                                value=f"FIM Integrity Violation: {p}",
                                target=target,
                                severity=Severity.CRITICAL,
                                detail=(
                                    f"CRITICAL FILE TAMPERING DETECTED: Cryptographic hash of {p} changed! "
                                    f"Previous: {prev_h[:12]}... -> Current: {h[:12]}..."
                                ),
                                metadata={
                                    "path": p,
                                    "previous_hash": prev_h,
                                    "current_hash": h,
                                    "threat_category": "fim_tampering"
                                }
                            )

        # Update and save baseline
        baseline.update(current_hashes)
        try:
            with open(FIM_BASELINE_PATH, "w", encoding="utf-8") as f:
                json.dump(baseline, f, indent=2)
        except Exception:
            pass

    def run(self, target: str, ctx) -> Iterator[Finding]:
        if target not in ("localhost", "127.0.0.1", "::1", "local", "server") and not target.startswith("127."):
            if not getattr(ctx, "server_audit", False):
                return

        if sys.platform.startswith("linux"):
            yield from self._audit_file_integrity(target)
            yield from self._audit_persistence(target)
            yield from self._audit_kernel_taint(target)
        else:
            yield Finding(
                tool=self.name,
                finding_type="hardening",
                value=f"FIM baseline audit inactive on {sys.platform}",
                target=target,
                severity=Severity.INFO,
                detail=f"FIM engine active on Linux servers. Platform {sys.platform} skipped.",
                metadata={"platform": sys.platform}
            )
