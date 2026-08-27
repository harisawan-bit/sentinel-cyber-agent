"""Cloud security posture — prowler-cloud/prowler (Apache-2.0)."""
from __future__ import annotations
import os, shutil, subprocess
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity


class ProwlerPlugin(Plugin):
    name = "prowler"
    description = "AWS/GCP/Azure security posture (prowler-cloud/prowler, Apache-2.0)"
    stage = "cloud"
    requires = ["prowler"]

    def run(self, target, ctx):
        if not os.environ.get("AWS_ACCESS_KEY_ID"):
            yield Finding(tool=self.name, finding_type="note",
                          value="prowler skipped: no AWS credentials in environment",
                          target=target, severity="info")
            return
        try:
            r = subprocess.run(["prowler", "aws", "--status", "FAIL"],
                               capture_output=True, text=True, timeout=600)
        except Exception as e:
            yield Finding(tool=self.name, finding_type="note", value=f"error: {e}",
                          target=target, severity="info")
            return
        for line in r.stdout.splitlines():
            if "FAIL" in line:
                yield Finding(tool=self.name, finding_type=FindingType.CLOUD_RESOURCE,
                              value=line.strip(), target=target, severity=Severity.MEDIUM)


# Copyleft engines (GPL/AGPL) are NOT imported here. They are invoked only as
# isolated external subprocesses so their license terms never reach the MIT core.
# Example wrapper pattern (kept out of the default pipeline):
#
# class SqlmapExternalPlugin(Plugin):
#     name = "sqlmap-external"
#     stage = "scan"
#     requires = ["sqlmap"]
#     def run(self, target, ctx):
#         # spawn `sqlmap -u <target> --batch` as a separate process; parse its
#         # stdout into Findings. sqlmap stays GPL-isolated.
#         ...
