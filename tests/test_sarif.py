"""Unit tests for Sentinel OASIS SARIF v2.1.0 exporter."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core.models import Finding
from sentinel.core.sarif import findings_to_sarif


def test_findings_to_sarif():
    findings = [
        Finding(
            tool="host_harden",
            finding_type="misconfiguration",
            value="kernel.randomize_va_space = 0",
            target="localhost",
            severity="critical",
            detail="ASLR is disabled",
            metadata={"mitigation": "ASLR"}
        ).to_dict(),
        Finding(
            tool="threat_intel",
            finding_type="vulnerability",
            value="CISA KEV Active Exploit: CVE-2023-38606",
            target="192.168.1.100",
            severity="critical",
            detail="In the wild",
            metadata={"cve": "CVE-2023-38606", "cisa_kev": True}
        ).to_dict(),
    ]

    sarif = findings_to_sarif(findings, run_title="Test Run")
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Sentinel"
    assert len(run["results"]) == 2

    # Check level mapping
    assert run["results"][0]["level"] == "error"
    assert "ASLR is disabled" in run["results"][0]["message"]["text"]
    assert run["results"][1]["properties"]["cve"] == "CVE-2023-38606"


if __name__ == "__main__":
    test_findings_to_sarif()
    print("PASS test_findings_to_sarif")
    print("ALL SARIF TESTS PASSED")
