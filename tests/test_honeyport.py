"""Unit tests for Sentinel Active Deception Honeyports."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core.plugins.honeyport_plugin import HoneyportPlugin, _record_trip, TRIPWIRE_LOG_FILE


def test_honeyport_plugin_instantiation():
    hp = HoneyportPlugin()
    assert hp.name == "honeyport"
    assert hp.stage == "audit"

    # Test clean run on localhost
    findings = list(hp.run("localhost", None))
    assert len(findings) >= 1
    assert any("Honeyport Deception Decoys" in f.value for f in findings)


def test_honeyport_record_trip():
    # Simulate a tripped event
    _record_trip("198.51.100.99", 23, "PROBE_TELNET_STRING")
    hp = HoneyportPlugin()
    findings = list(hp.run("localhost", None))
    trip_f = next((f for f in findings if "198.51.100.99" in f.value), None)
    assert trip_f is not None
    assert trip_f.severity == "critical"
    assert "PROBE_TELNET_STRING" in trip_f.detail
    assert "iptables -I INPUT -s 198.51.100.99 -j DROP" in trip_f.metadata["iptables_ban"]


if __name__ == "__main__":
    test_honeyport_plugin_instantiation()
    print("PASS test_honeyport_plugin_instantiation")
    test_honeyport_record_trip()
    print("PASS test_honeyport_record_trip")
    print("ALL HONEYPORT TESTS PASSED")
