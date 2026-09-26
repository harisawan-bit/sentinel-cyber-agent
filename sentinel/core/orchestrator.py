"""Plugin discovery + pipeline orchestration."""
from __future__ import annotations
import importlib, os, pkgutil, shutil, traceback
from typing import Dict, List, Optional, Any

from .config import bin_path
from .models import Finding
from .plugin import Plugin


STAGE_ORDER = ["recon", "scan", "osint", "cloud", "audit", "intel"]


class Orchestrator:
    def __init__(self) -> None:
        self.plugins: Dict[str, Plugin] = {}
        self.shared: Dict[str, Any] = {"techs": []}  # cross-plugin state
        self.all_findings: List[Finding] = []
        self.discovered_cves: List[str] = []
        self.server_audit: bool = False
        self.load_plugins()

    def load_plugins(self) -> None:
        import sentinel.core.plugins as plugins_pkg  # absolute import avoids circular import
        for mod in pkgutil.iter_modules(plugins_pkg.__path__):
            try:
                m = importlib.import_module(f"sentinel.core.plugins.{mod.name}")
            except Exception:
                continue
            for attr in dir(m):
                obj = getattr(m, attr)
                if (
                    isinstance(obj, type)
                    and issubclass(obj, Plugin)
                    and obj is not Plugin
                ):
                    try:
                        inst = obj()
                    except Exception:
                        continue
                    self.plugins[inst.name] = inst

    def missing_requirements(self, name: str) -> List[str]:
        """Return the external binaries a plugin needs that are not installed.

        Plugin.requires was declared by every engine-backed plugin but never
        consulted, so a missing binary surfaced as an opaque "plugin error"
        note. The orchestrator now checks it up front and skips the plugin
        with a clear reason.
        """
        plugin = self.plugins.get(name)
        if plugin is None:
            return []
        missing = []
        for binary in plugin.requires:
            if shutil.which(binary) is None and not os.path.isfile(bin_path(binary)):
                missing.append(binary)
        return missing

    def run(self, targets: List[str], stages: Optional[set] = None) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        # Sort plugins by pipeline stage order
        stage_rank = {s: i for i, s in enumerate(STAGE_ORDER)}
        sorted_plugins = sorted(
            self.plugins.items(),
            key=lambda item: stage_rank.get(item[1].stage, 99)
        )
        for target in targets:
            for name, p in sorted_plugins:
                if stages and p.stage not in stages:
                    continue
                # Engine-backed plugins are skipped with a clear reason when
                # their binary is absent, rather than failing opaquely.
                missing = self.missing_requirements(name)
                if missing:
                    findings.append(
                        Finding(
                            tool=name, finding_type="note",
                            value=f"{name} skipped: missing {', '.join(missing)}",
                            target=target, severity="info",
                            detail=(
                                f"Plugin '{name}' requires {', '.join(missing)}. "
                                f"Run scripts/install_engines.py or install manually."
                            ),
                        ).to_dict()
                    )
                    continue
                try:
                    for f in p.run(target, self):
                        d = f.to_dict()
                        findings.append(d)
                        self.all_findings.append(f)
                        # collect tech tokens for OSV correlation
                        if f.finding_type == "host":
                            for tk in (f.metadata or {}).get("tech", []):
                                token = tk.split("=", 1)[-1].lower()
                                if token and token not in self.shared["techs"]:
                                    self.shared["techs"].append(token)
                except Exception as e:  # graceful degradation
                    findings.append(
                        Finding(
                            tool=name, finding_type="note", value=f"plugin error: {e}",
                            target=target, severity="info",
                            detail=traceback.format_exc()[-500:],
                        ).to_dict()
                    )
        return findings
