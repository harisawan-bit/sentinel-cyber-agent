"""Deception & Honeytoken Canary Auditor for 0-Day Detection.

Pure-Python, zero external dependencies.
Since 0-day exploits cannot be matched with prior signatures, deceptive honeytokens
provide definitive, zero-false-positive alerts:
If an attacker exploits an unrevealed vulnerability and conducts internal host reconnaissance,
accessing a canary file (e.g. decoy .env, fake SSH private key, dummy database config)
immediately triggers a CRITICAL incident alert.
"""
from __future__ import annotations
import hashlib, json, os, time
from typing import Iterator, Dict, Any, List
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity

DEFAULT_CANARY_PATHS = [
    ".canary_token",
    "/etc/sentinel/canary.token",
    "/var/www/html/.env.canary",
    "/root/.ssh/id_rsa.canary",
]


class CanaryAuditPlugin(Plugin):
    name = "canary_audit"
    description = "Audit deception honeytokens and canary files for 0-day post-exploitation detection"
    stage = "audit"
    requires = []

    def _hash_file(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()

    def run(self, target: str, ctx) -> Iterator[Finding]:
        if target not in ("localhost", "127.0.0.1", "::1", "local", "server") and not target.startswith("127."):
            if not getattr(ctx, "server_audit", False):
                return

        # Check for any existing registered canaries or local canary files
        state_dir = os.path.expanduser("~/.sentinel")
        canary_manifest = os.path.join(state_dir, "canaries.json")

        monitored_canaries: List[Dict[str, Any]] = []
        if os.path.isfile(canary_manifest):
            try:
                with open(canary_manifest, "r", encoding="utf-8") as f:
                    monitored_canaries = json.load(f)
            except Exception:
                pass

        if not monitored_canaries:
            # Check default local canary if present
            local_canary = os.path.abspath(".canary_token")
            if os.path.exists(local_canary):
                monitored_canaries.append({
                    "path": local_canary,
                    "created_at": os.path.getctime(local_canary),
                    "baseline_hash": self._hash_file(local_canary),
                    "baseline_atime": os.path.getatime(local_canary),
                })

        if not monitored_canaries:
            yield Finding(
                tool=self.name,
                finding_type="note",
                value="No active honeytokens registered",
                target=target,
                severity=Severity.INFO,
                detail="No canary honeytokens found. Register canary decoys with Sentinel to detect 0-day intrusions.",
                metadata={"status": "unconfigured"}
            )
            return

        for canary in monitored_canaries:
            path = canary.get("path")
            if not path or not os.path.exists(path):
                continue

            try:
                st = os.stat(path)
                curr_atime = st.st_atime
                curr_mtime = st.st_mtime
                base_atime = canary.get("baseline_atime", 0)
                base_hash = canary.get("baseline_hash")

                curr_hash = self._hash_file(path)

                # Check if file content tampered
                if base_hash and curr_hash != base_hash:
                    yield Finding(
                        tool=self.name,
                        finding_type=FindingType.VULNERABILITY,
                        value=f"Canary Honeytoken Modified: {path}",
                        target=target,
                        severity=Severity.CRITICAL,
                        detail=(
                            f"CRITICAL 0-DAY BREACH ALERT: Decoy honeytoken file '{path}' has been tampered with or modified. "
                            f"Definitive evidence of unauthorized internal actor access."
                        ),
                        metadata={
                            "canary_path": path,
                            "baseline_hash": base_hash,
                            "current_hash": curr_hash,
                            "threat_category": "deception_compromise"
                        }
                    )
                # Check if accessed (read)
                elif base_atime and curr_atime > (base_atime + 1):
                    yield Finding(
                        tool=self.name,
                        finding_type=FindingType.VULNERABILITY,
                        value=f"Canary Honeytoken Read: {path}",
                        target=target,
                        severity=Severity.HIGH,
                        detail=(
                            f"DECEPTION ALERT: Canary decoy file '{path}' was read. "
                            f"Unauthorized inspection of decoy credentials or sensitive decoy paths."
                        ),
                        metadata={
                            "canary_path": path,
                            "accessed_at": curr_atime,
                            "threat_category": "canary_read"
                        }
                    )
                else:
                    yield Finding(
                        tool=self.name,
                        finding_type="hardening",
                        value=f"Canary Honeytoken Armed: {path}",
                        target=target,
                        severity=Severity.INFO,
                        detail=f"Honeytoken '{path}' is pristine and armed. Zero-day tripwire active.",
                        metadata={"canary_path": path, "status": "armed"}
                    )
            except Exception:
                continue
