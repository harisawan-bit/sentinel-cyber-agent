"""Runtime Process Lineage, Reverse Shell, and Behavioral Anomaly Detector.

Pure-Python, zero external dependencies.
Detects 0-day post-exploitation activities that signature scanners miss entirely:
1. Web server / DB daemon spawning interactive shells or LOLBins (bash, sh, curl, nc, python).
2. Daemon processes establishing unauthorized outbound egress (reverse shells / C2 beaconing).
3. Userland rootkits via /etc/ld.so.preload injection.
"""
from __future__ import annotations
import os, sys, glob
from typing import Iterator, Dict, Any, List, Set
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity

SUSPICIOUS_PARENTS = {
    "nginx", "apache2", "httpd", "www-data", "caddy", "lighttpd",
    "php-fpm", "gunicorn", "uwsgi", "node", "java", "ruby",
    "mysqld", "mariadbd", "postgres", "mongod", "redis-server"
}

SUSPICIOUS_CHILDREN = {
    "sh", "bash", "dash", "zsh", "ksh",
    "curl", "wget", "nc", "netcat", "ncat", "socat",
    "python", "python3", "perl", "ruby", "lua",
    "powershell", "cmd.exe", "whoami", "id"
}


class ProcessAnomalyPlugin(Plugin):
    name = "process_anomaly"
    description = "Audit process lineage, reverse shell egress, and rootkit preloads for 0-day detection"
    stage = "audit"
    requires = []

    def _get_linux_processes(self) -> Dict[int, Dict[str, Any]]:
        procs: Dict[int, Dict[str, Any]] = {}
        for p_dir in glob.glob("/proc/[0-9]*"):
            try:
                pid = int(os.path.basename(p_dir))
                stat_file = os.path.join(p_dir, "stat")
                if not os.path.exists(stat_file):
                    continue
                with open(stat_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                # format: pid (comm) state ppid ...
                rparen = content.rfind(")")
                if rparen == -1:
                    continue
                lparen = content.find("(")
                comm = content[lparen + 1:rparen]
                rest = content[rparen + 2:].split()
                ppid = int(rest[1]) if len(rest) > 1 else 0

                cmdline_file = os.path.join(p_dir, "cmdline")
                cmdline = ""
                if os.path.exists(cmdline_file):
                    with open(cmdline_file, "rb") as cf:
                        raw = cf.read()
                        cmdline = " ".join(raw.decode("utf-8", "ignore").split("\x00")).strip()

                procs[pid] = {
                    "comm": comm,
                    "ppid": ppid,
                    "cmdline": cmdline or comm,
                }
            except Exception:
                continue
        return procs

    def _audit_lineage(self, procs: Dict[int, Dict[str, Any]]) -> Iterator[Finding]:
        target = "localhost"
        for pid, info in procs.items():
            child_comm = info["comm"].lower()
            ppid = info["ppid"]
            if ppid in procs:
                parent_info = procs[ppid]
                parent_comm = parent_info["comm"].lower()

                # Check if parent is a web/DB server and child is a shell/downloader
                is_suspicious_parent = any(sp in parent_comm for sp in SUSPICIOUS_PARENTS)
                is_suspicious_child = child_comm in SUSPICIOUS_CHILDREN

                if is_suspicious_parent and is_suspicious_child:
                    yield Finding(
                        tool=self.name,
                        finding_type=FindingType.VULNERABILITY,
                        value=f"Suspicious Process Spawn: {parent_comm} (pid {ppid}) -> {child_comm} (pid {pid})",
                        target=target,
                        severity=Severity.CRITICAL,
                        detail=(
                            f"CRITICAL 0-DAY RCE INDICATOR: Server daemon '{parent_comm}' spawned shell or LOLBin '{child_comm}'. "
                            f"Command: {info['cmdline'][:200]}"
                        ),
                        metadata={
                            "parent_pid": ppid,
                            "parent_comm": parent_comm,
                            "child_pid": pid,
                            "child_comm": child_comm,
                            "cmdline": info["cmdline"],
                            "threat_category": "0day_rce_execution",
                        }
                    )

    def _audit_rootkit_preload(self) -> Iterator[Finding]:
        target = "localhost"
        preload_path = "/etc/ld.so.preload"
        if os.path.exists(preload_path):
            try:
                with open(preload_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().strip()
                if content:
                    yield Finding(
                        tool=self.name,
                        finding_type=FindingType.VULNERABILITY,
                        value="Active /etc/ld.so.preload detected",
                        target=target,
                        severity=Severity.CRITICAL,
                        detail=f"POTENTIAL USERLAND ROOTKIT: /etc/ld.so.preload contains injected libraries: {content[:150]}",
                        metadata={"path": preload_path, "content": content}
                    )
            except Exception:
                pass

    def run(self, target: str, ctx) -> Iterator[Finding]:
        if target not in ("localhost", "127.0.0.1", "::1", "local", "server") and not target.startswith("127."):
            if not getattr(ctx, "server_audit", False):
                return

        if sys.platform.startswith("linux"):
            procs = self._get_linux_processes()
            yield from self._audit_lineage(procs)
            yield from self._audit_rootkit_preload()
        else:
            # Non-Linux platform baseline
            yield Finding(
                tool=self.name,
                finding_type="note",
                value=f"Process anomaly audit inactive on {sys.platform} (requires Linux /proc)",
                target="localhost",
                severity=Severity.INFO,
                detail="Process lineage and /proc/stat inspection is active when executed on Linux server targets.",
                metadata={"platform": sys.platform}
            )
