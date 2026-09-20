"""Unit tests for Homelab cyber security modules: LAN scanner, notifiers, state diff, and ports matrix."""
from __future__ import annotations
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core.models import Finding, Severity, FindingType
from sentinel.core.plugins.lan_scanner_plugin import LanScannerPlugin
from sentinel.core.notifiers import format_digest
from sentinel.core.state import diff_and_update_state
from sentinel.core.report import render


def test_lan_scanner_instantiation():
    plugin = LanScannerPlugin()
    assert plugin.name == "lan_scanner"
    assert plugin.stage == "recon"


def test_notifiers_format_digest():
    findings = [
        Finding("lan_scanner", FindingType.PORT, "8006/tcp", "192.168.1.50", Severity.MEDIUM, detail="Proxmox VE Console", metadata={"service": "Proxmox"}).to_dict(),
        Finding("lan_scanner", FindingType.PORT, "2375/tcp", "192.168.1.50", Severity.CRITICAL, detail="Docker Daemon (Raw TCP)", metadata={"service": "Docker"}).to_dict(),
    ]
    digest = format_digest(findings, title="Homelab Audit")
    assert "SENTINEL HOMELAB DIGEST" in digest
    assert "8006/tcp" in digest
    assert "2375/tcp" in digest
    assert "Critical: 1" in digest


def test_state_drift_detection():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        state_file = tf.name

    try:
        # First scan
        initial = [Finding("t", "port", "22/tcp", "192.168.1.50", "info").to_dict()]
        drift1 = diff_and_update_state(initial, state_file)
        assert len(drift1) == 0  # no drift on first run

        # Second scan with new port
        second = [
            Finding("t", "port", "22/tcp", "192.168.1.50", "info").to_dict(),
            Finding("t", "port", "8006/tcp", "192.168.1.50", "medium", detail="Proxmox").to_dict(),
        ]
        drift2 = diff_and_update_state(second, state_file)
        assert len(drift2) == 1
        assert "NEW PORT DETECTED" in drift2[0]["detail"]
    finally:
        if os.path.exists(state_file):
            os.remove(state_file)


def test_report_renders_open_ports_matrix():
    findings = [
        Finding("lan_scanner", FindingType.PORT, "8006/tcp", "192.168.1.50", Severity.MEDIUM, detail="Proxmox VE Console", metadata={"service": "Proxmox", "category": "Hypervisor"}).to_dict(),
        Finding("lan_scanner", FindingType.PORT, "22/tcp", "192.168.1.50", Severity.INFO, detail="SSH", metadata={"service": "SSH", "category": "Remote Access"}).to_dict(),
    ]
    html = render(findings, title="Homelab Test")
    assert "Open Ports &amp; Services Matrix" in html
    assert "ports-card" in html
    assert "8006/tcp" in html
    assert "Proxmox" in html
    assert "port-filters" in html


if __name__ == "__main__":
    for fn in (test_lan_scanner_instantiation, test_notifiers_format_digest,
               test_state_drift_detection, test_report_renders_open_ports_matrix):
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception as e:
            print(f"FAIL {fn.__name__}: {e}")
            sys.exit(1)
    print("ALL HOMELAB TESTS PASSED")
