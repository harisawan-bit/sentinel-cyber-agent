"""Plugin interface. Every engine is a Plugin subclass."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Iterable, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Finding
    from .orchestrator import Orchestrator


class Plugin(ABC):
    name: str = "unnamed"
    description: str = ""
    stage: str = "recon"          # recon | scan | osint | cloud
    requires: list = []           # external binary names this plugin shells out to

    @abstractmethod
    def run(self, target: str, ctx: "Orchestrator") -> Iterable["Finding"]:
        """Yield Finding objects for the given target."""
        raise NotImplementedError
