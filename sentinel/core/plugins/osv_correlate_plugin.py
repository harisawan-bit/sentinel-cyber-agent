"""Technology -> vulnerability correlation via OSV (Google Open Source Vulnerabilities).

Pure-Python, MIT, no binary. Takes tech fingerprints discovered by other
plugins (passed through ctx.shared) and queries the OSV API for known CVEs.
This is the "merge the best" glue: recon findings become a prioritized
vulnerability list without a separate manual step.
"""
from __future__ import annotations
import json, re, urllib.request
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity

OSV_API = "https://api.osv.dev/v1/query"

# map common fingerprint tokens -> OSV package (ecosystem, name)
PKG_MAP = {
    "wordpress": ("Packagist", "wordpress/wordpress"),
    "cloudflare": None,  # infra, not a package
    "nginx": ("Debian", "nginx") if False else ("", "nginx"),
    "apache": ("", "httpd"),
    "php": ("", "php"),
    "openssl": ("", "openssl"),
    "jquery": ("npm", "jquery"),
    "drupal": ("Packagist", "drupal/drupal"),
    "spring": ("Maven", "org.springframework:spring-core"),
    "tomcat": ("", "tomcat"),
    "node.js": ("npm", "node"),
    "python": ("PyPI", "python"),
    "rails": ("RubyGems", "rails"),
    "django": ("PyPI", "django"),
    "redis": ("", "redis"),
}

_SEV_ORDER = {"LOW": Severity.LOW, "MODERATE": Severity.MEDIUM,
              "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH,
              "CRITICAL": Severity.CRITICAL}


def _osv_query(ecosystem: str, name: str) -> list:
    body = json.dumps({"package": {"ecosystem": ecosystem, "name": name}}).encode()
    req = urllib.request.Request(OSV_API, data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode("utf-8", "ignore")).get("vulns", [])
    except Exception:
        return []


class OsvCorrelatePlugin(Plugin):
    name = "osv-correlate"
    description = "Map discovered tech to known CVEs via OSV (no binary)"
    stage = "scan"
    requires = []

    def run(self, target, ctx):
        # gather tech tokens from prior findings in this run (shared dict on ctx)
        techs = set()
        shared = getattr(ctx, "shared", None)
        if shared is not None:
            for t in shared.get("techs", []):
                techs.add(t.lower())
        # also pull from the tech metadata of already-emitted host findings
        for f in getattr(ctx, "all_findings", []) or []:
            ftype = f.get("finding_type") if isinstance(f, dict) else getattr(f, "finding_type", "")
            if ftype == "host":
                meta = (f.get("metadata", {}) if isinstance(f, dict) else getattr(f, "metadata", {})) or {}
                for tk in meta.get("tech", []):
                    m = re.match(r".*=([\w.\-]+)", tk)
                    if m:
                        techs.add(m.group(1).lower())

        seen_cve = set()
        for token in techs:
            pkg = PKG_MAP.get(token)
            if not pkg or not pkg[0]:
                continue
            eco, name = pkg
            for v in _osv_query(eco, name):
                vid = v.get("id")
                if not vid or vid in seen_cve:
                    continue
                seen_cve.add(vid)
                sev = Severity.INFO
                for s in (v.get("severity") or []):
                    sev = _SEV_ORDER.get((s.get("score") or "").upper(), sev)
                # severity may live under database_specific
                ds = v.get("database_specific") or {}
                if ds.get("severity"):
                    sev = _SEV_ORDER.get(ds["severity"].upper(), sev)
                yield Finding(
                    tool=self.name, finding_type=FindingType.VULNERABILITY,
                    value=f"{name}: {vid}", target=target, severity=sev.value,
                    detail=(v.get("summary") or "")[:200],
                    metadata={"ecosystem": eco, "package": name, "osv_id": vid},
                )
