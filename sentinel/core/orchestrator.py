"""Plugin discovery + pipeline orchestration."""
from __future__ import annotations
import importlib, pkgutil, traceback
from typing import Dict, List, Optional, Any

from .models import Finding
from .plugin import Plugin


class Orchestrator:
    def __init__(self) -> None:
        self.plugins: Dict[str, Plugin] = {}
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
                    inst = obj()
                    self.plugins[inst.name] = inst

    def run(self, targets: List[str], stages: Optional[set] = None) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for target in targets:
            for name, p in self.plugins.items():
                if stages and p.stage not in stages:
                    continue
                try:
                    for f in p.run(target, self):
                        findings.append(f.to_dict())
                except Exception as e:  # graceful degradation
                    findings.append(
                        Finding(
                            tool=name, finding_type="note", value=f"plugin error: {e}",
                            target=target, severity="info",
                            detail=traceback.format_exc()[-500:],
                        ).to_dict()
                    )
        return findings
