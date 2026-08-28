"""SQL injection scanning — sqlmap (GPL-2.0).

*** LICENSE ISOLATION ***
sqlmap is GPL-2.0. It is NEVER imported or vendored into the MIT core. This
plugin only ever invokes the `sqlmap` binary as a separate OS process and
parses its stdout. Running it as an external command keeps the GPL terms
confined to that subprocess; the MIT Sentinel core stays clean.

To use: install sqlmap separately (e.g. `pip install sqlmap` or clone upstream)
and ensure `sqlmap` is on PATH. This plugin will not run unless the binary
exists.
"""
from __future__ import annotations
import json, os, shutil, subprocess, re
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity

_SEV = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
        "high": Severity.HIGH, "critical": Severity.CRITICAL}


class SqlmapExternalPlugin(Plugin):
    name = "sqlmap-external"
    description = "SQLi detection via sqlmap (GPL-2.0) — invoked as ISOLATED external process only"
    stage = "scan"
    requires = ["sqlmap"]

    def run(self, target, ctx):
        bin = shutil.which("sqlmap") or shutil.which("sqlmap.py")
        if not bin:
            yield Finding(tool=self.name, finding_type="note",
                          value="sqlmap not installed (GPL-2.0 engine runs externally; install separately)",
                          target=target, severity="info")
            return
        try:
            r = subprocess.run(
                [bin, "-u", target, "--batch", "--disable-coloring",
                 "--level=1", "--risk=1", "--output-dir=/tmp/sentinel_sqlmap"],
                capture_output=True, text=True, timeout=600,
            )
        except Exception as e:
            yield Finding(tool=self.name, finding_type="note", value=f"error: {e}",
                          target=target, severity="info")
            return
        out = r.stdout + r.stderr
        # sqlmap prints lines like:  [<severity>] [<dbms>] <payload>
        for m in re.finditer(r"\[(\w+)\]\s+(.*)", out):
            sev = _SEV.get(m.group(1).lower(), Severity.INFO)
            yield Finding(tool=self.name, finding_type=FindingType.VULNERABILITY,
                          value=target, target=target, severity=sev.value,
                          detail=m.group(2).strip()[:200])
