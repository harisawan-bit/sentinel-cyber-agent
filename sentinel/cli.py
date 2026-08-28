"""Command-line entry point."""
from __future__ import annotations
import argparse, json, sys
from .core.orchestrator import Orchestrator
from .core.report import render


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel — unified MIT-licensed cyber security agent",
    )
    ap.add_argument("targets", nargs="+", help="targets: domains, hostnames, or usernames")
    ap.add_argument("--stages", nargs="*",
                    help="limit to stages: recon scan osint cloud")
    ap.add_argument("--json", action="store_true", help="emit raw JSON")
    ap.add_argument("--out", default=None, help="write findings JSON to file")
    ap.add_argument("--report", default=None, help="write autonomous HTML report to file")
    args = ap.parse_args(argv)

    orch = Orchestrator()
    stages = set(args.stages) if args.stages else None
    findings = orch.run(args.targets, stages=stages)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)

    if args.report:
        html = render(findings, title=" · ".join(args.targets[:3]))
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(html)

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print(f"Sentinel: {len(findings)} findings")
        for f in findings[:80]:
            print(f"  [{f['severity']:<8}] {f['finding_type']:<14} {f['value']}  ({f['tool']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
