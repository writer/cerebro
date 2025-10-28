"""Telemetry domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cerebro.core.database import Base
from cerebro.core.database_types import JSONType
from cerebro.core.models import Organization, Resource


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


class HostTelemetryEvent(Base):
    """Persistent host event emitted by endpoint agents."""

    __tablename__ = "host_telemetry_events"

    event_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("orgs.org_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    account_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("accounts.account_id", ondelete="SET NULL"),
        nullable=True,
    )
    resource_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("resources.resource_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    host_id: Mapped[str] = mapped_column(String(255), nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    process_id: Mapped[Optional[int]] = mapped_column(nullable=True)
    parent_pid: Mapped[Optional[int]] = mapped_column(nullable=True)
    user: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    command_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    payload: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    organization: Mapped[Organization] = relationship("Organization")
    resource: Mapped[Optional[Resource]] = relationship("Resource")

