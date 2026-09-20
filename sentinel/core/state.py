"""Lightweight state and drift detection engine for homelabs.

Tracks discovered ports and hosts between runs to alert on configuration drift.
Zero third-party dependencies — uses standard library json.
"""
from __future__ import annotations
import json, os
from typing import List, Dict, Any

from sentinel.core.models import Finding, FindingType, Severity


def diff_and_update_state(findings: List[Dict[str, Any]], state_path: str = ".sentinel_state.json") -> List[Dict[str, Any]]:
    prev_state: Dict[str, List[str]] = {}
    if os.path.exists(state_path):
        try:
            with open(state_path, "r", encoding="utf-8") as f:
                prev_state = json.load(f)
        except Exception:
            prev_state = {}

    curr_state: Dict[str, List[str]] = {}
    drift_findings: List[Dict[str, Any]] = []

    for f in findings:
        target = f.get("target", "?")
        val = f"{f.get('finding_type')}:{f.get('value')}"
        curr_state.setdefault(target, []).append(val)

        # Check if target existed before and if this port/finding is brand new
        if target in prev_state and val not in prev_state[target]:
            ftype = f.get("finding_type", "")
            prefix = "NEW PORT DETECTED" if ftype == "port" else "NEW ASSET/FINDING"
            drift_findings.append(
                Finding(
                    tool="state_diff",
                    finding_type=FindingType.NOTE,
                    value=f"drift:{f.get('value')}",
                    target=target,
                    severity=Severity.HIGH if f.get("severity") in ("critical", "high") else Severity.MEDIUM,
                    detail=f"🚨 [{prefix}] {f.get('value')} on {target} ({f.get('detail', '')})",
                ).to_dict()
            )

    try:
        with open(state_path, "w", encoding="utf-8") as f:
            json.dump(curr_state, f, indent=2)
    except Exception:
        pass

    return drift_findings
