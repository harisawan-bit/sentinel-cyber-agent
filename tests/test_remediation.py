"""Unit tests for Sentinel Autonomous Remediation engine."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core.remediation import (
    plan_remediation,
    generate_hardening_conf,
    apply_remediation,
    generate_firewall_drop,
    HARDENING_PARAMS
)


def test_generate_hardening_conf():
    conf = generate_hardening_conf()
    assert "kernel.randomize_va_space = 2" in conf
    assert "kernel.unprivileged_userns_clone = 0" in conf
    assert "fs.protected_symlinks = 1" in conf
    assert "net.ipv4.conf.all.rp_filter = 1" in conf


def test_plan_remediation():
    plan = plan_remediation()
    assert len(plan) == len(HARDENING_PARAMS)
    aslr_plan = next(p for p in plan if p["param"] == "kernel.randomize_va_space")
    assert aslr_plan["target"] == "2"
    assert "Full ASLR" in aslr_plan["description"]


def test_apply_remediation_dry_run():
    res = apply_remediation(dry_run=True)
    assert res["status"] in ("dry_run", "unsupported_platform")
    assert "conf_preview" in res
    assert "total_checked" in res
    assert res["total_checked"] == len(HARDENING_PARAMS)


def test_generate_firewall_drop():
    rules = generate_firewall_drop("198.51.100.42")
    assert "198.51.100.42" in rules["iptables"]
    assert "198.51.100.42" in rules["nftables"]
    assert "198.51.100.42" in rules["ufw"]


if __name__ == "__main__":
    for fn in (
        test_generate_hardening_conf,
        test_plan_remediation,
        test_apply_remediation_dry_run,
        test_generate_firewall_drop,
    ):
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception as e:
            print(f"FAIL {fn.__name__}: {e}")
            sys.exit(1)
    print("ALL REMEDIATION TESTS PASSED")
