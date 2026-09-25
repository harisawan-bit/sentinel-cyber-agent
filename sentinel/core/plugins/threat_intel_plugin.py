"""Threat Intelligence Engine: CISA KEV & FIRST EPSS Scoring.

Pure-Python, zero external dependencies.
Correlates discovered CVEs against:
1. CISA Known Exploited Vulnerabilities (KEV) Catalog:
   Flags whether a CVE is being actively exploited in the wild by threat actors.
2. FIRST Exploit Prediction Scoring System (EPSS):
   Predicts the probability (0.00 to 1.00) of exploitation within 30 days.

This allows security teams to prioritize latest revealed CVEs and weaponized exploits immediately.
"""
from __future__ import annotations
import json, re, urllib.request
from typing import Iterator, Dict, Any, List, Set
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity

CISA_KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"

_KEV_CACHE: Set[str] = set()
_KEV_LOADED: bool = False


def _load_cisa_kev(timeout: int = 8) -> Set[str]:
    global _KEV_CACHE, _KEV_LOADED
    if _KEV_LOADED:
        return _KEV_CACHE
    try:
        req = urllib.request.Request(CISA_KEV_API, headers={"User-Agent": "Sentinel-Cyber-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
            vulns = data.get("vulnerabilities", [])
            _KEV_CACHE = {v.get("cveID", "").upper() for v in vulns if v.get("cveID")}
            _KEV_LOADED = True
    except Exception:
        # Graceful degradation if CISA feed is offline or rate-limited
        _KEV_LOADED = True
    return _KEV_CACHE


def _query_epss(cve_ids: List[str], timeout: int = 8) -> Dict[str, float]:
    """Query FIRST.org EPSS scores for a batch of CVE IDs."""
    scores: Dict[str, float] = {}
    if not cve_ids:
        return scores
    joined = ",".join(cve_ids[:30])  # Batch limit
    url = f"{EPSS_API}?cve={joined}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Sentinel-Cyber-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
            for entry in data.get("data", []):
                cid = entry.get("cve", "").upper()
                try:
                    score = float(entry.get("epss", 0.0))
                    scores[cid] = score
                except (ValueError, TypeError):
                    pass
    except Exception:
        pass
    return scores


class ThreatIntelPlugin(Plugin):
    name = "threat_intel"
    description = "Correlate discovered CVEs against CISA KEV (in-the-wild exploitation) and EPSS scoring"
    stage = "intel"
    requires = []

    def run(self, target: str, ctx) -> Iterator[Finding]:
        # Collect CVE IDs from findings generated so far
        cves: Set[str] = set()
        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

        # Check explicitly stored CVEs on ctx
        for c in getattr(ctx, "discovered_cves", []) or []:
            m = cve_pattern.search(c)
            if m:
                cves.add(m.group(0).upper())

        # Check all findings emitted so far
        for f in getattr(ctx, "all_findings", []) or []:
            val = f.get("value", "") if isinstance(f, dict) else getattr(f, "value", "")
            detail = f.get("detail", "") if isinstance(f, dict) else getattr(f, "detail", "")
            for match in cve_pattern.findall(f"{val} {detail}"):
                cves.add(match.upper())

        if not cves:
            return

        cve_list = sorted(list(cves))
        kev_set = _load_cisa_kev()
        epss_map = _query_epss(cve_list)

        for cve in cve_list:
            is_in_kev = cve in kev_set
            epss_score = epss_map.get(cve)

            # 1. CISA KEV Alert (Active in-the-wild exploitation)
            if is_in_kev:
                yield Finding(
                    tool=self.name,
                    finding_type=FindingType.VULNERABILITY,
                    value=f"CISA KEV Active Exploit: {cve}",
                    target=target,
                    severity=Severity.CRITICAL,
                    detail=(
                        f"CRITICAL THREAT: {cve} is listed in CISA's Known Exploited Vulnerabilities catalog. "
                        f"Active in-the-wild weaponization confirmed by federal threat intelligence."
                    ),
                    metadata={
                        "cve": cve,
                        "cisa_kev": True,
                        "in_the_wild": True,
                        "epss_score": epss_score,
                    }
                )

            # 2. High EPSS Warning (Imminent weaponization probability > 50%)
            if epss_score is not None and epss_score >= 0.50:
                pct = epss_score * 100
                yield Finding(
                    tool=self.name,
                    finding_type="threat_intel",
                    value=f"High EPSS Score: {cve} ({pct:.1f}% probability)",
                    target=target,
                    severity=Severity.HIGH,
                    detail=(
                        f"PREDICTIVE EXPLOIT THREAT: EPSS model calculates a {pct:.1f}% probability of active "
                        f"exploitation in the wild within 30 days."
                    ),
                    metadata={
                        "cve": cve,
                        "epss_score": epss_score,
                        "epss_percentile": pct,
                    }
                )
