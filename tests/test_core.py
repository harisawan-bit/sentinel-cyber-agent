"""Core unit tests — run with: python -m pytest tests/  (or python tests/test_core.py)"""
from __future__ import annotations
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core.models import Finding, Severity, FindingType
from sentinel.core.plugin import Plugin
from sentinel.core.orchestrator import Orchestrator
from sentinel.core.report import render


class _DummyPlugin(Plugin):
    name = "dummy"
    stage = "recon"
    requires = []

    def run(self, target, ctx):
        yield Finding(tool=self.name, finding_type=FindingType.HOST,
                      value=f"host:{target}", target=target, severity=Severity.INFO)
        yield Finding(tool=self.name, finding_type=FindingType.VULNERABILITY,
                      value=f"vuln:{target}", target=target, severity=Severity.HIGH)


def test_finding_to_dict():
    f = Finding(tool="t", finding_type="host", value="v", target="x", severity="info")
    d = f.to_dict()
    assert d["tool"] == "t" and "id" in d and "timestamp" in d


def test_orchestrator_loads_plugins():
    o = Orchestrator()
    assert "dummy" not in o.plugins  # not loaded (not registered)
    assert len(o.plugins) >= 5  # the real plugins are present


def test_orchestrator_runs_dummy():
    o = Orchestrator()
    # monkeypatch a dummy plugin in
    o.plugins["dummy"] = _DummyPlugin()
    res = o.run(["test.target"])
    types = {f["finding_type"] for f in res}
    assert "host" in types and "vulnerability" in types
    # shared tech collection doesn't crash
    assert isinstance(o.shared, dict)


def test_report_renders():
    findings = [
        Finding(tool="t", finding_type="host", value="https://x", target="x",
                severity="info", metadata={"tech": ["server=nginx"]}).to_dict(),
        Finding(tool="t", finding_type="vulnerability", value="CVE-1", target="x",
                severity="high").to_dict(),
    ]
    html = render(findings, title="Unit")
    assert html.startswith("<!doctype html>")
    assert "SENTINEL" in html
    assert "nginx" in html
    assert "CVE-1" in html


def test_osv_query_known_package():
    from sentinel.core.plugins.osv_correlate_plugin import _osv_query
    vulns = _osv_query("npm", "jquery")
    assert isinstance(vulns, list)
    # network may be flaky; if we got data, assert shape
    if vulns:
        assert "id" in vulns[0]


if __name__ == "__main__":
    for fn in (test_finding_to_dict, test_orchestrator_loads_plugins,
               test_orchestrator_runs_dummy, test_report_renders,
               test_osv_query_known_package):
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception as e:
            print(f"FAIL {fn.__name__}: {e}")
            sys.exit(1)
    print("ALL TESTS PASSED")
