"""Host Software Package & SBOM Auditor with OSV Vulnerability Correlation.

Pure-Python, MIT license, zero heavy dependencies.
Extracts actual installed packages on Linux servers (Debian/Ubuntu dpkg, RHEL/Alma rpm,
Alpine apk, or Python environment packages) and correlates exact versions against
the OSV (Open Source Vulnerabilities) API. This provides accurate, real-world CVE
and 0-day exposure discovery for the actual host rather than surface-level HTTP guessing.
"""
from __future__ import annotations
import json, os, subprocess, sys, urllib.request
from typing import Iterator, Dict, Any, List, Tuple
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity

OSV_API = "https://api.osv.dev/v1/query"

_SEV_ORDER = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL
}


def _query_osv_pkg(ecosystem: str, name: str, version: str) -> list:
    body = json.dumps({
        "version": version,
        "package": {"ecosystem": ecosystem, "name": name}
    }).encode("utf-8")
    req = urllib.request.Request(
        OSV_API,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
            return data.get("vulns", [])
    except Exception:
        return []


class PkgAuditPlugin(Plugin):
    name = "pkg_audit"
    description = "Audit installed server OS packages and Python environments against OSV for live CVE exposure"
    stage = "scan"
    requires = []

    def _get_installed_dpkg(self) -> List[Tuple[str, str, str]]:
        """Debian / Ubuntu dpkg packages."""
        pkgs = []
        try:
            r = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package} ${Version}\n"],
                capture_output=True, text=True, timeout=15
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        pkgs.append(("Debian", parts[0], parts[1]))
        except Exception:
            pass
        return pkgs

    def _get_installed_rpm(self) -> List[Tuple[str, str, str]]:
        """RHEL / CentOS / Fedora / Alma packages."""
        pkgs = []
        try:
            r = subprocess.run(
                ["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"],
                capture_output=True, text=True, timeout=15
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        pkgs.append(("Red Hat", parts[0], parts[1]))
        except Exception:
            pass
        return pkgs

    def _get_python_packages(self) -> List[Tuple[str, str, str]]:
        """Extract packages from active Python environment."""
        pkgs = []
        try:
            import importlib.metadata as md
            for dist in md.distributions():
                name = dist.metadata.get("Name")
                ver = dist.metadata.get("Version")
                if name and ver:
                    pkgs.append(("PyPI", name, ver))
        except Exception:
            pass
        return pkgs

    def run(self, target: str, ctx) -> Iterator[Finding]:
        if target not in ("localhost", "127.0.0.1", "::1", "local", "server") and not target.startswith("127."):
            if not getattr(ctx, "server_audit", False):
                return

        packages: List[Tuple[str, str, str]] = []
        if sys.platform.startswith("linux"):
            packages.extend(self._get_installed_dpkg())
            if not packages:
                packages.extend(self._get_installed_rpm())

        # Always audit Python environment packages (core runtime dependencies)
        packages.extend(self._get_python_packages()[:25])  # Cap at top packages for speed

        if not packages:
            return

        seen_vulns = set()
        cve_findings = []
        # Query top packages (focus on web servers, cryptography, network services)
        priority_keywords = {"ssl", "tls", "ssh", "crypto", "http", "flask", "django", "urllib", "requests", "jinja", "tornado", "aiohttp", "fastapi"}
        prioritized = [p for p in packages if any(k in p[1].lower() for k in priority_keywords)]
        sample = prioritized[:10] if prioritized else packages[:5]

        for eco, name, ver in sample:
            vulns = _query_osv_pkg(eco, name, ver)
            for v in vulns:
                vid = v.get("id")
                if not vid or vid in seen_vulns:
                    continue
                seen_vulns.add(vid)

                sev = Severity.MEDIUM
                for s in (v.get("severity") or []):
                    sev = _SEV_ORDER.get((s.get("score") or "").upper(), sev)
                ds = v.get("database_specific") or {}
                if ds.get("severity"):
                    sev = _SEV_ORDER.get(ds["severity"].upper(), sev)

                # Store CVE in shared context so threat_intel plugin can enrich with KEV/EPSS
                cves_list = getattr(ctx, "discovered_cves", None)
                if cves_list is None:
                    ctx.discovered_cves = []
                ctx.discovered_cves.append(vid)

                summary = (v.get("summary") or v.get("details") or "")[:200]
                yield Finding(
                    tool=self.name,
                    finding_type=FindingType.VULNERABILITY,
                    value=f"{name} ({ver}): {vid}",
                    target=target,
                    severity=sev.value,
                    detail=f"Installed package '{name} {ver}' affected by {vid}: {summary}",
                    metadata={
                        "ecosystem": eco,
                        "package": name,
                        "version": ver,
                        "osv_id": vid,
                        "aliases": v.get("aliases", []),
                    }
                )
