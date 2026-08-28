"""Subdomain enumeration via Certificate Transparency logs (crt.sh).

Pure-Python, MIT, no binary. Queries the public crt.sh API for certificates
matching a domain and extracts subdomains. Same role as subfinder but with
zero external dependency — fills the recon stage even when the PD binaries
are unavailable.
"""
from __future__ import annotations
import json, re, ssl, urllib.request
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity


class CrtshPlugin(Plugin):
    name = "crtsh"
    description = "Subdomain discovery via Certificate Transparency (crt.sh, no binary)"
    stage = "recon"
    requires = []

    _URL = "https://crt.sh/?q={domain}&output=json"

    def run(self, target, ctx):
        domain = target.split("/")[0].split(":")[0]
        if domain.startswith("http"):
            domain = domain.split("://", 1)[1]
        url = self._URL.format(domain=domain)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Sentinel/0.1"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode("utf-8", "ignore"))
        except Exception as e:
            yield Finding(tool=self.name, finding_type="note",
                          value=f"crt.sh query failed: {e}", target=target, severity="info")
            return
        seen = set()
        for entry in data:
            name = (entry.get("name_value") or "").strip()
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if not sub or "*" in sub:
                    continue
                if sub.endswith(domain) and sub not in seen:
                    seen.add(sub)
                    yield Finding(tool=self.name, finding_type=FindingType.SUBDOMAIN,
                                  value=sub, target=target, severity=Severity.INFO)
