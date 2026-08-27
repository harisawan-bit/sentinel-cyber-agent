"""Passive subdomain enumeration — projectdiscovery/subfinder (MIT)."""
from __future__ import annotations
import shutil, subprocess
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity
from ..config import bin_path


class SubfinderPlugin(Plugin):
    name = "subfinder"
    description = "Passive subdomain enumeration (projectdiscovery/subfinder, MIT)"
    stage = "recon"
    requires = ["subfinder"]

    def run(self, target, ctx):
        bin = bin_path("subfinder")
        if shutil.which(bin) is None and not _exists(bin):
            yield Finding(tool=self.name, finding_type="note",
                          value="subfinder not installed (run scripts/install_engines.py)",
                          target=target, severity="info")
            return
        try:
            r = subprocess.run([bin, "-d", target, "-silent"],
                               capture_output=True, text=True, timeout=300)
        except Exception as e:
            yield Finding(tool=self.name, finding_type="note", value=f"error: {e}",
                          target=target, severity="info")
            return
        for line in r.stdout.splitlines():
            s = line.strip()
            if s:
                yield Finding(tool=self.name, finding_type=FindingType.SUBDOMAIN,
                              value=s, target=target, severity=Severity.INFO)


def _exists(p):
    import os
    return os.path.isfile(p)
