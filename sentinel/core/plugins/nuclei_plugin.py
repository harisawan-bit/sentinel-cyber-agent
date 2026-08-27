"""Vulnerability scanning — projectdiscovery/nuclei (MIT)."""
from __future__ import annotations
import json, shutil, subprocess
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity
from ..config import bin_path

_SEV = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
        "high": Severity.HIGH, "critical": Severity.CRITICAL}


class NucleiPlugin(Plugin):
    name = "nuclei"
    description = "Template-based vuln/misconfig scanning (projectdiscovery/nuclei, MIT)"
    stage = "scan"
    requires = ["nuclei"]

    def run(self, target, ctx):
        bin = bin_path("nuclei")
        if shutil.which(bin) is None and not _exists(bin):
            yield Finding(tool=self.name, finding_type="note",
                          value="nuclei not installed (run scripts/install_engines.py)",
                          target=target, severity="info")
            return
        try:
            r = subprocess.run([bin, "-u", target, "-silent", "-json",
                                "-severity", "low,medium,high,critical"],
                               capture_output=True, text=True, timeout=600)
        except Exception as e:
            yield Finding(tool=self.name, finding_type="note", value=f"error: {e}",
                          target=target, severity="info")
            return
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            yield Finding(tool=self.name, finding_type=FindingType.VULNERABILITY,
                          value=d.get("matched-at", target),
                          target=target,
                          severity=_SEV.get(d.get("severity", "info"), Severity.INFO).value,
                          detail=d.get("info", {}).get("name") if isinstance(d.get("info"), dict) else None,
                          metadata={"template": d.get("template-id"), "type": d.get("type")})


def _exists(p):
    import os
    return os.path.isfile(p)
