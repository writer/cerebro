"""Telemetry domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
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


class ArtifactPack(Base):
    """Artifact pack definition distributed to endpoint agents."""

    __tablename__ = "artifact_packs"

    pack_id: Mapped[UUID] = mapped_column(
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
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    selectors: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True, default=dict)
    enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True, server_default=sa.true())
    approval_state: Mapped[str] = mapped_column(String(32), nullable=False, default="draft", server_default="draft")
    approval_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    schedule_interval_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    last_deployed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    organization: Mapped[Organization] = relationship("Organization")
    tasks: Mapped[list["ArtifactPackTask"]] = relationship(
        "ArtifactPackTask",
        back_populates="pack",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    # Automation rules that determine when this pack should execute.
    triggers: Mapped[list["ArtifactPackTrigger"]] = relationship(
        "ArtifactPackTrigger",
        back_populates="pack",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    # Host-specific assignments created by the control plane.
    targets: Mapped[list["ArtifactPackTarget"]] = relationship(
        "ArtifactPackTarget",
        back_populates="pack",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ArtifactPackTask(Base):
    """Task entry belonging to an artifact pack."""

    __tablename__ = "artifact_pack_tasks"

    task_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    pack_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("artifact_packs.pack_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    collector: Mapped[str] = mapped_column(String(128), nullable=False)
    interval_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    tags: Mapped[Optional[Dict[str, str]]] = mapped_column(JSONType, nullable=True, default=dict)
    config: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True, default=dict)
    discovery: Mapped[Optional[List[str]]] = mapped_column(JSONType, nullable=True, default=list)
    parameters: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSONType, nullable=True, default=list)
    parameter_values: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True, default=dict)
    resources: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True, default=dict)
    tools: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSONType, nullable=True, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    pack: Mapped[ArtifactPack] = relationship("ArtifactPack", back_populates="tasks")


class ArtifactPackTrigger(Base):
    """Automation rule that determines when an artifact pack should execute."""

    __tablename__ = "artifact_pack_triggers"

    trigger_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    pack_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("artifact_packs.pack_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    trigger_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="Classifier for the trigger (e.g., event_type, event_category)",
    )
    match_value: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Concrete value that must be matched by incoming telemetry",
    )
    minimum_severity: Mapped[Optional[str]] = mapped_column(
        String(16),
        nullable=True,
        doc="Optional severity threshold that must be met or exceeded",
    )
    expires_after_seconds: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        doc="How long the trigger assignment remains valid for a host",
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    pack: Mapped[ArtifactPack] = relationship("ArtifactPack", back_populates="triggers")


class ArtifactPackTarget(Base):
    """Represents a host-specific assignment to run a particular artifact pack."""

    __tablename__ = "artifact_pack_targets"

    target_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    pack_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("artifact_packs.pack_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    host_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        doc="Stable identifier for the endpoint that must run the pack",
    )
    hostname: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        doc="Friendly host name recorded when the target was issued",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        doc="When the target was generated",
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Optional expiry timestamp after which the target is ignored",
    )
    fulfilled_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Moment the agent acknowledged or completed the pack execution",
    )

    pack: Mapped[ArtifactPack] = relationship("ArtifactPack", back_populates="targets")

