"""Live host probing — projectdiscovery/httpx (MIT)."""
from __future__ import annotations
import json, shutil, subprocess
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity
from ..config import bin_path


class HttpxPlugin(Plugin):
    name = "httpx"
    description = "Live host probing + tech detection (projectdiscovery/httpx, MIT)"
    stage = "recon"
    requires = ["httpx"]

    def run(self, target, ctx):
        bin = bin_path("httpx")
        if shutil.which(bin) is None and not _exists(bin):
            yield Finding(tool=self.name, finding_type="note",
                          value="httpx not installed (run scripts/install_engines.py)",
                          target=target, severity="info")
            return
        try:
            r = subprocess.run([bin, "-u", target, "-silent", "-json"],
                               capture_output=True, text=True, timeout=300)
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
            sev = Severity.INFO
            if d.get("status_code", 0) >= 400:
                sev = Severity.LOW
            meta = {k: d.get(k) for k in ("status_code", "title", "tech", "webserver", "scheme") if k in d}
            yield Finding(tool=self.name, finding_type=FindingType.HOST,
                          value=d.get("url", target), target=target,
                          severity=sev, metadata=meta)


def _exists(p):
    import os
    return os.path.isfile(p)
