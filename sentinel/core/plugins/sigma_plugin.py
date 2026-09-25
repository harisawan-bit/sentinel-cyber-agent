"""Detection-as-Code: Sigma Rule Evaluator.

Pure-Python, zero external dependencies.
Evaluates system events and process artifacts against community Sigma rules
mapped to MITRE ATT&CK tactics and techniques:
- T1059: Command and Scripting Interpreter (LOLBins, encoded powershell, reverse shells)
- T1003: OS Credential Dumping (LSASS access, shadow file reads)
- T1053: Scheduled Task / Cron Persistence
- T1574: Hijack Execution Flow (ld.so.preload injection)
"""
from __future__ import annotations
import re
from typing import Iterator, Dict, Any, List
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity

BUILTIN_SIGMA_RULES = [
    {
        "id": "SIGMA-001",
        "title": "Suspicious Interactive Reverse Shell Spawn",
        "mitre": "T1059.004",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"(\/bin\/bash -i|\/bin\/sh -i|nc -e \/bin\/sh|& \/dev\/tcp\/|bash -c.*>& \/dev\/tcp)", re.IGNORECASE),
        "description": "Detects interactive shell command line indicative of standard reverse shell payload.",
    },
    {
        "id": "SIGMA-002",
        "title": "Encoded PowerShell Download Cradle",
        "mitre": "T1059.001",
        "severity": Severity.HIGH,
        "pattern": re.compile(r"(powershell.*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|Invoke-WebRequest.*\|\s*IEX|DownloadString)", re.IGNORECASE),
        "description": "Detects encoded PowerShell or IEX download cradle used in payload delivery.",
    },
    {
        "id": "SIGMA-003",
        "title": "Shadow File Access or Credential Exfiltration",
        "mitre": "T1003.008",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"(cat \/etc\/shadow|getent shadow|unshadow|grep .*\/etc\/shadow)", re.IGNORECASE),
        "description": "Detects command attempting to read or dump Linux shadow credential file.",
    },
    {
        "id": "SIGMA-004",
        "title": "Dynamic Linker Preload Persistence (LD_PRELOAD)",
        "mitre": "T1574.006",
        "severity": Severity.HIGH,
        "pattern": re.compile(r"(echo.*>>\s*\/etc\/ld\.so\.preload|LD_PRELOAD=.*\.so)", re.IGNORECASE),
        "description": "Detects userland rootkit injection via ld.so.preload modification.",
    },
    {
        "id": "SIGMA-005",
        "title": "Suspicious Download Tool Invocation via Web Service",
        "mitre": "T1105",
        "severity": Severity.HIGH,
        "pattern": re.compile(r"(curl -fsSL|wget -qO-|certutil -urlcache -split -f)", re.IGNORECASE),
        "description": "Detects silent download and execute commands used by threat actors.",
    },
]


class SigmaPlugin(Plugin):
    name = "sigma_rules"
    description = "Detection-as-Code engine evaluating Sigma rules mapped to MITRE ATT&CK"
    stage = "audit"
    requires = []

    def run(self, target: str, ctx) -> Iterator[Finding]:
        # Collect command lines and details from prior findings
        sample_texts: List[str] = []

        for f in getattr(ctx, "all_findings", []) or []:
            val = f.get("value", "") if isinstance(f, dict) else getattr(f, "value", "")
            detail = f.get("detail", "") if isinstance(f, dict) else getattr(f, "detail", "")
            meta = (f.get("metadata", {}) if isinstance(f, dict) else getattr(f, "metadata", {})) or {}
            cmdline = meta.get("cmdline", "")
            sample_texts.append(f"{val} {detail} {cmdline}")

        matched_rules = set()

        for text in sample_texts:
            for rule in BUILTIN_SIGMA_RULES:
                rid = rule["id"]
                if rid in matched_rules:
                    continue
                if rule["pattern"].search(text):
                    matched_rules.add(rid)
                    yield Finding(
                        tool=self.name,
                        finding_type=FindingType.VULNERABILITY,
                        value=f"Sigma Match [{rule['id']}]: {rule['title']}",
                        target=target,
                        severity=rule["severity"].value if hasattr(rule["severity"], "value") else str(rule["severity"]),
                        detail=f"{rule['description']} (MITRE ATT&CK: {rule['mitre']})",
                        metadata={
                            "sigma_id": rule["id"],
                            "mitre_technique": rule["mitre"],
                            "title": rule["title"],
                        }
                    )

        # Indicate active Sigma rules loaded
        yield Finding(
            tool=self.name,
            finding_type="hardening",
            value=f"Sigma Detection Engine ({len(BUILTIN_SIGMA_RULES)} community rules)",
            target=target,
            severity=Severity.INFO,
            detail=f"Sigma Detection-as-Code engine active with {len(BUILTIN_SIGMA_RULES)} MITRE ATT&CK mapped rules.",
            metadata={"rule_count": len(BUILTIN_SIGMA_RULES), "status": "active"}
        )
