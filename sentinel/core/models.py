"""Shared finding model used by every plugin and the orchestrator."""
from __future__ import annotations
import time, uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class FindingType(str, Enum):
    SUBDOMAIN = "subdomain"
    HOST = "host"
    PORT = "port"
    TECHNOLOGY = "technology"
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    ACCOUNT = "account"
    CLOUD_RESOURCE = "cloud_resource"
    HARDENING = "hardening"
    ANOMALY = "anomaly"
    THREAT_INTEL = "threat_intel"
    CANARY = "canary"
    NOTE = "note"


@dataclass
class Finding:
    tool: str
    finding_type: str
    value: str
    target: str
    severity: str = "info"
    detail: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def __post_init__(self) -> None:
        if hasattr(self.severity, "value"):
            self.severity = str(self.severity.value)
        if hasattr(self.finding_type, "value"):
            self.finding_type = str(self.finding_type.value)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
