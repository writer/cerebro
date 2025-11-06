"""Database models supporting compliance pre-audit health checks."""

from __future__ import annotations

import enum
from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from cerebro.core.database import Base, engine


def _json_type() -> JSON | JSONB:
    """Return a JSON-capable column type that works for both SQLite and Postgres."""

    # PostgreSQL engines expose the PGUUID driver name at runtime, but SQLAlchemy
    # will happily coerce JSONB values for SQLite provided we avoid driver-specific
    # column classes when unavailable. JSONB offers richer querying on Postgres
    # while remaining compatible with SQLite's text storage.
    try:
        dialect = engine.dialect.name
    except Exception:  # pragma: no cover - defensive for edge bootstrap cases
        dialect = "sqlite"

    return JSONB if dialect.startswith("postgres") else JSON


class AuditScheduleStatus(str, enum.Enum):
    """Lifecycle state for compliance audit schedules."""

    SCHEDULED = "scheduled"
    ACTIVE = "active"
    READY = "ready"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class PreAuditRunStatus(str, enum.Enum):
    """Execution status for individual pre-audit health check runs."""

    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"


class ControlHealthStatus(str, enum.Enum):
    """Outcome for a single compliance control within a run."""

    PASSING = "passing"
    FAILING = "failing"
    AT_RISK = "at_risk"
    MISSING_EVIDENCE = "missing_evidence"


class ComplianceAuditSchedule(Base):
    """Tracks upcoming audits and when pre-audit checks should execute."""

    __tablename__ = "compliance_audit_schedules"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), index=True, nullable=False)
    frameworks: Mapped[List[str]] = mapped_column(_json_type(), nullable=False)
    audit_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    prep_window_weeks: Mapped[int] = mapped_column(Integer, default=4, nullable=False)
    owner_emails: Mapped[List[str]] = mapped_column(_json_type(), default=list, nullable=False)
    auto_assign_tasks: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    create_tickets: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[AuditScheduleStatus] = mapped_column(
        Enum(AuditScheduleStatus), default=AuditScheduleStatus.SCHEDULED, nullable=False
    )
    ready_notification_sent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    runs: Mapped[List["PreAuditRun"]] = relationship(
        "PreAuditRun", back_populates="schedule", cascade="all, delete-orphan"
    )


class PreAuditRun(Base):
    """Represents a single execution of the pre-audit health check."""

    __tablename__ = "compliance_pre_audit_runs"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    schedule_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("compliance_audit_schedules.id", ondelete="CASCADE"), nullable=False
    )
    run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    status: Mapped[PreAuditRunStatus] = mapped_column(
        Enum(PreAuditRunStatus), default=PreAuditRunStatus.RUNNING, nullable=False
    )
    summary: Mapped[dict] = mapped_column(_json_type(), default=dict, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    passing_controls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failing_controls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    at_risk_controls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    missing_controls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    estimated_outcome: Mapped[str] = mapped_column(String(128), default="pending", nullable=False)

    schedule: Mapped[ComplianceAuditSchedule] = relationship("ComplianceAuditSchedule", back_populates="runs")
    findings: Mapped[List["PreAuditControlFinding"]] = relationship(
        "PreAuditControlFinding", back_populates="run", cascade="all, delete-orphan"
    )


class PreAuditControlFinding(Base):
    """Detailed status for each control evaluated during a run."""

    __tablename__ = "compliance_pre_audit_findings"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    run_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("compliance_pre_audit_runs.id", ondelete="CASCADE"), nullable=False
    )
    framework_name: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    control_title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[ControlHealthStatus] = mapped_column(
        Enum(ControlHealthStatus), nullable=False
    )
    pass_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence_summary: Mapped[dict] = mapped_column(_json_type(), default=dict, nullable=False)
    issue_summary: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    remediation_suggestion: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    priority: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    task_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True, index=True)
    ticket_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )

    run: Mapped[PreAuditRun] = relationship("PreAuditRun", back_populates="findings")


__all__ = [
    "AuditScheduleStatus",
    "ControlHealthStatus",
    "PreAuditRunStatus",
    "ComplianceAuditSchedule",
    "PreAuditRun",
    "PreAuditControlFinding",
]
