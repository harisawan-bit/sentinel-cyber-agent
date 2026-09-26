"""Unit tests for Sentinel Active Deception Honeyports.

Runs against a throwaway SENTINEL_HOME so the developer's real ~/.sentinel
is never written to. Honeyport trips are real breach indicators — leaking
test fixtures into that directory makes the next real audit report a
phantom CRITICAL.
"""
from __future__ import annotations
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Sandbox BEFORE importing anything that resolves a state path.
_TMP_HOME = tempfile.mkdtemp(prefix="sentinel_test_home_")
os.environ["SENTINEL_HOME"] = _TMP_HOME

from sentinel.core.paths import state_path  # noqa: E402
from sentinel.core.plugins.honeyport_plugin import HoneyportPlugin, _record_trip  # noqa: E402

_real_home = os.path.join(os.path.expanduser("~"), ".sentinel")


def _cleanup():
    import shutil
    shutil.rmtree(_TMP_HOME, ignore_errors=True)
    os.environ.pop("SENTINEL_HOME", None)


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


def test_tests_do_not_touch_real_home():
    """Regression: state must land in SENTINEL_HOME, never ~/.sentinel."""
    assert state_path("honeyport_trips.json").startswith(_TMP_HOME)
    assert os.path.isfile(os.path.join(_TMP_HOME, "honeyport_trips.json"))
    if os.path.isdir(_real_home):
        leaked = [
            f for f in os.listdir(_real_home)
            if "198.51.100.99" in open(os.path.join(_real_home, f), errors="ignore").read()
        ]
        assert not leaked, f"test fixtures leaked into real state dir: {leaked}"


if __name__ == "__main__":
    try:
        test_honeyport_plugin_instantiation()
        print("PASS test_honeyport_plugin_instantiation")
        test_honeyport_record_trip()
        print("PASS test_honeyport_record_trip")
        test_tests_do_not_touch_real_home()
        print("PASS test_tests_do_not_touch_real_home")
        print("ALL HONEYPORT TESTS PASSED")
    finally:
        _cleanup()
