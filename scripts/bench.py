#!/usr/bin/env python3
"""Measure Sentinel's memory footprint so the README claims are reproducible.

Usage:
    python3 scripts/bench.py            # measure + print table
    python3 scripts/bench.py --json     # machine-readable

Measures peak RSS of a full `--server-audit` cycle and of each long-running
daemon mode, then prints the result against the documented budget.
"""
from __future__ import annotations
import argparse, json, os, resource, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

BUDGET_MB = 25.0


def _rss_mb() -> float:
    """Peak RSS of this process tree, in MB (Linux ru_maxrss is KiB)."""
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def measure_audit() -> dict:
    """Run one full server-audit cycle in a child and record its peak RSS."""
    code = (
        "import resource,sys;sys.path.insert(0,%r);"
        "from sentinel.core.orchestrator import Orchestrator;"
        "o=Orchestrator();o.server_audit=True;"
        "o.run(['localhost'],stages={'audit','intel','scan'});"
        "print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)"
        % ROOT
    )
    t0 = time.time()
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        return {"name": "server-audit", "error": r.stderr.strip()[-300:]}
    return {
        "name": "server-audit",
        "peak_rss_mb": round(int(r.stdout.strip().splitlines()[-1]) / 1024.0, 2),
        "seconds": round(time.time() - t0, 2),
    }


def measure_import_baseline() -> dict:
    """Cost of importing the package with no work done — the daemon's floor."""
    code = (
        "import resource,sys;sys.path.insert(0,%r);"
        "import sentinel.core.orchestrator;"
        "print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)" % ROOT
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return {"name": "import-baseline", "error": r.stderr.strip()[-300:]}
    return {
        "name": "import-baseline",
        "peak_rss_mb": round(int(r.stdout.strip().splitlines()[-1]) / 1024.0, 2),
    }


def measure_native() -> dict:
    """Size of the compiled C daemon, if built."""
    binary = os.path.join(ROOT, "bin", "sentineld")
    if not os.path.isfile(binary):
        return {"name": "sentineld (native)", "error": "not built — run `make`"}
    return {
        "name": "sentineld (native)",
        "binary_kb": round(os.path.getsize(binary) / 1024.0, 1),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure Sentinel memory footprint")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    results = [measure_import_baseline(), measure_audit(), measure_native()]

    if args.json:
        print(json.dumps({"results": results, "budget_mb": BUDGET_MB}, indent=2))
        return 0

    print(f"{'component':<22} {'metric':<14} {'value':>10}   budget")
    print("-" * 62)
    worst = 0.0
    for r in results:
        if "error" in r:
            print(f"{r['name']:<22} {'-':<14} {'n/a':>10}   {r['error']}")
            continue
        if "binary_kb" in r:
            print(f"{r['name']:<22} {'binary':<14} {str(r['binary_kb'])+' KB':>10}")
            continue
        mb = r["peak_rss_mb"]
        worst = max(worst, mb)
        flag = "OK" if mb <= BUDGET_MB else "OVER"
        extra = f"   {r['seconds']}s" if "seconds" in r else ""
        print(f"{r['name']:<22} {'peak RSS':<14} {str(mb)+' MB':>10}   <= {BUDGET_MB} MB  [{flag}]{extra}")
    print()
    print(f"Worst-case peak RSS: {worst} MB (budget {BUDGET_MB} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
