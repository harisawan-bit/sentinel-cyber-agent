"""Username OSINT — sherlock-project/sherlock (MIT).

Robust: drives sherlock with `--csv --folderoutput`, then parses the
machine-readable CSV (username,name,url_main,url_user,exists,http_status,...)
instead of scraping stdout. Per-site failures are sherlock's problem; we
only care about the rows it manages to write.
"""
from __future__ import annotations
import os, csv, glob, subprocess, sys, tempfile
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity

# Major sites that reliably accept this egress IP; extend as needed.
DEFAULT_SITES = ["GitHub", "Reddit", "YouTube", "Instagram", "Twitter", "GitLab"]


class SherlockPlugin(Plugin):
    name = "sherlock"
    description = "Username presence across sites (sherlock-project/sherlock, MIT)"
    stage = "osint"
    requires = ["sherlock"]

    def run(self, target, ctx):
        outdir = tempfile.mkdtemp(prefix="sentinel_sherlock_")
        cmd = [sys.executable, "-m", "sherlock_project.sherlock", target,
               "--csv", "--folderoutput", outdir, "--no-color"]
        for s in DEFAULT_SITES:
            cmd += ["--site", s]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except Exception as e:
            yield Finding(tool=self.name, finding_type="note", value=f"error: {e}",
                          target=target, severity="info")
            return
        # parse CSVs
        for csvf in glob.glob(os.path.join(outdir, "*.csv")):
            try:
                with open(csvf, newline="", encoding="utf-8") as fh:
                    reader = csv.DictReader(fh)
                    for row in reader:
                        if (row.get("exists") or "").strip().lower() in ("true", "claim", "claimed"):
                            yield Finding(
                                tool=self.name, finding_type=FindingType.ACCOUNT,
                                value=row.get("url_user") or row.get("url_main", target),
                                target=target, severity=Severity.INFO,
                                detail=f"{row.get('name')} (HTTP {row.get('http_status')})",
                                metadata={"site": row.get("name"),
                                          "http_status": row.get("http_status")},
                            )
            except Exception:
                continue
