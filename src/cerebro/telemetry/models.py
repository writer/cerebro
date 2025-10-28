"""Telemetry domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from uuid import UUID


@dataclass(frozen=True)
class RepositoryContext:
    """Resolved context for repository telemetry."""

    org_id: UUID
    org_name: str
    account_id: UUID
    account_provider: str
    resource_id: UUID
    resource_type: str
    resource_external_id: str
    resource_name: Optional[str]
    received_at: datetime
    metadata: Dict[str, Any]


@dataclass(frozen=True)
class RuntimeContext:
    """Resolved context for runtime telemetry."""

    org_id: UUID
    account_id: UUID
    resource_id: UUID
    service_name: str
    environment: str
    received_at: datetime
    metadata: Dict[str, Any]


@dataclass(frozen=True)
class HostContext:
    """Resolved context for endpoint/desktop telemetry."""

    org_id: UUID
    account_id: UUID
    resource_id: UUID
    host_id: str
    hostname: str
    received_at: datetime
    metadata: Dict[str, Any]


@dataclass(frozen=True)
class TelemetryResult:
    """Summary of telemetry processing outcomes."""

    findings_created: int = 0
    findings_updated: int = 0
    findings: Tuple[UUID, ...] = field(default_factory=tuple)
    metadata: Dict[str, Any] = field(default_factory=dict)

