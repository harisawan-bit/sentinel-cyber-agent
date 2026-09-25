"""OASIS SARIF v2.1.0 Exporter for Sentinel Findings.

Allows findings to be natively imported into:
- GitHub Advanced Security / Code Scanning
- GitLab Security Dashboard
- DefectDojo / OWASP tools
- Enterprise SIEM & Vulnerability Management platforms
"""
from __future__ import annotations
import json
from typing import Dict, List, Any


def findings_to_sarif(findings: List[Dict[str, Any]], run_title: str = "Sentinel Assessment") -> Dict[str, Any]:
    """Convert Sentinel findings into OASIS SARIF v2.1.0 JSON format."""
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    sev_to_sarif = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
        "unknown": "none",
    }

    for f in findings:
        tool_name = f.get("tool", "sentinel")
        finding_id = f.get("id", "SENTINEL-001")
        rule_id = f"{tool_name}/{f.get('finding_type', 'vuln')}"
        sev = str(f.get("severity", "info")).lower()
        level = sev_to_sarif.get(sev, "note")

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("/", "_").replace("-", "_"),
                "shortDescription": {"text": f"Sentinel check: {rule_id}"},
                "fullDescription": {"text": f"Security finding produced by Sentinel plugin '{tool_name}'"},
                "defaultConfiguration": {"level": level},
                "help": {"text": f"Review {f.get('target', 'host')} configuration or patch identified vulnerability."},
            }

        meta = f.get("metadata") or {}
        cve = meta.get("cve") or meta.get("osv_id") or ""
        detail = f.get("detail") or f.get("value") or ""

        result_entry: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"[{sev.upper()}] {f.get('value', '')}: {detail}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": str(f.get("target", "localhost")),
                        },
                        "region": {
                            "startLine": 1,
                        }
                    }
                }
            ],
            "properties": {
                "severity": sev,
                "tool": tool_name,
                "findingType": f.get("finding_type"),
                "cve": cve,
                "metadata": meta,
            }
        }
        results.append(result_entry)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel",
                        "version": "2.1.0",
                        "informationUri": "https://github.com/harisawan-bit/sentinel-cyber-agent",
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": run_title,
                    }
                ],
                "results": results,
            }
        ]
    }
    return sarif_doc
