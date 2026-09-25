"""Unit tests for Sentinel continuous daemon and systemd integration."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core.orchestrator import Orchestrator
from sentinel.core.daemon import generate_systemd_unit, run_daemon_loop


def test_generate_systemd_unit():
    unit = generate_systemd_unit(
        exec_cmd="/usr/bin/sentinel --server-audit --daemon",
        user="sentinel_user",
        group="sentinel_grp",
        workdir="/var/sentinel"
    )
    assert "[Unit]" in unit
    assert "[Service]" in unit
    assert "User=sentinel_user" in unit
    assert "ExecStart=/usr/bin/sentinel --server-audit --daemon" in unit
    assert "Restart=always" in unit
    assert "ProtectSystem=full" in unit


def test_daemon_loop_single_cycle():
    orch = Orchestrator()
    # Run a single cycle with max_cycles=1 to verify clean execution
    run_daemon_loop(
        orch=orch,
        targets=["localhost"],
        interval=1,
        stages={"audit"},
        max_cycles=1,
    )


if __name__ == "__main__":
    test_generate_systemd_unit()
    print("PASS test_generate_systemd_unit")
    test_daemon_loop_single_cycle()
    print("PASS test_daemon_loop_single_cycle")
    print("ALL DAEMON TESTS PASSED")
