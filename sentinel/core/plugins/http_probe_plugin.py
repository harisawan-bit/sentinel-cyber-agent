"""Native HTTP recon — pure-Python, MIT (no external engine required).

This plugin is first-party Sentinel code (MIT) so it works with zero binary
downloads. It performs a live probe + header/tech fingerprint and emits
Finding objects in the shared model. Useful as a baseline even when the
projectdiscovery binaries are not installed.
"""
from __future__ import annotations
import re, socket, ssl, subprocess, sys
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity


class HttpProbePlugin(Plugin):
    name = "http-probe"
    description = "Native HTTP probe + header/tech fingerprint (first-party MIT)"
    stage = "recon"
    requires = []

    _TECH_HINTS = {
        "server": "webserver",
        "x-powered-by": "backend",
        "x-aspnet-version": "ASP.NET",
        "x-generator": "generator",
        "set-cookie": "session-tech",
    }
    _SEV_BY_CODE = {
        200: Severity.INFO, 301: Severity.LOW, 302: Severity.LOW,
        401: Severity.LOW, 403: Severity.LOW, 404: Severity.LOW,
        500: Severity.MEDIUM, 502: Severity.MEDIUM, 503: Severity.MEDIUM,
    }

    def run(self, target, ctx):
        # normalise to a host we can connect to
        host = target
        for prefix in ("https://", "http://"):
            if host.startswith(prefix):
                host = host[len(prefix):]
        host = host.split("/")[0].split(":")[0]

        # DNS resolution check
        try:
            socket.gethostbyname(host)
        except Exception:
            yield Finding(tool=self.name, finding_type="note",
                          value=f"DNS resolution failed for {host}",
                          target=target, severity="info")
            return

        for scheme in ("https", "http"):
            import requests
            url = f"{scheme}://{host}"
            try:
                r = requests.get(url, timeout=15, allow_redirects=False,
                                 headers={"User-Agent": "Sentinel/0.1 (+recon)"})
            except Exception as e:
                yield Finding(tool=self.name, finding_type="note",
                              value=f"{scheme} probe error: {e}",
                              target=target, severity="info")
                continue
            sev = self._SEV_BY_CODE.get(r.status_code, Severity.INFO)
            tech = []
            for h, v in r.headers.items():
                lh = h.lower()
                if lh in self._TECH_HINTS:
                    tech.append(f"{self._TECH_HINTS[lh]}={v}")
                if lh == "server":
                    tech.append(f"server={v}")
            body_snip = r.text[:2000]
            if re.search(r"wordpress", body_snip, re.I):
                tech.append("CMS=WordPress")
            if re.search(r"cloudflare", " ".join(r.headers.get("server", "") + str(r.headers.get("cf-ray", ""))), re.I):
                tech.append("CDN=Cloudflare")
            yield Finding(
                tool=self.name, finding_type=FindingType.HOST,
                value=url, target=target, severity=sev,
                detail=f"HTTP {r.status_code}",
                metadata={"status_code": r.status_code,
                          "title": (re.search(r"<title>(.*?)</title>", body_snip, re.I).group(1) if re.search(r"<title>(.*?)</title>", body_snip, re.I) else None),
                          "tech": tech[:8]},
            )
