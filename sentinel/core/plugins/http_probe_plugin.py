"""Native HTTP recon — pure-Python, MIT (no external engine required).

This plugin is first-party Sentinel code (MIT) so it works with zero binary
downloads. It performs a live probe + header/tech fingerprint and emits
Finding objects in the shared model. Useful as a baseline even when the
projectdiscovery binaries are not installed.
"""
from __future__ import annotations
import re, socket, ssl, subprocess, sys, urllib.error, urllib.request
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity

_UA = "Sentinel/2.4.0 (+recon)"


class _Resp:
    """Minimal response shim so we keep the requests-like field access below."""

    __slots__ = ("status_code", "headers", "text")

    def __init__(self, status_code: int, headers: dict, text: str):
        self.status_code = status_code
        self.headers = _CaseInsensitive(headers)
        self.text = text


class _CaseInsensitive(dict):
    """HTTP header map with case-insensitive lookup (RFC 9110 field names)."""

    def __init__(self, items: dict):
        super().__init__({str(k).lower(): v for k, v in items.items()})

    def get(self, key, default=None):
        return super().get(str(key).lower(), default)

    def __getitem__(self, key):
        return super().__getitem__(str(key).lower())


def _http_get(url: str, timeout: int = 15) -> _Resp:
    """GET without following redirects, using only the standard library.

    urllib raises HTTPError for 4xx/5xx; those are legitimate recon results
    here, so they are converted into responses rather than exceptions.
    """
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(200_000)
            return _Resp(r.status, dict(r.headers), raw.decode("utf-8", "ignore"))
    except urllib.error.HTTPError as e:
        raw = e.read(200_000) if hasattr(e, "read") else b""
        return _Resp(e.code, dict(e.headers or {}), raw.decode("utf-8", "ignore"))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface 3xx as a status code instead of silently following the chain."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
            url = f"{scheme}://{host}"
            try:
                r = _http_get(url, timeout=15)
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
