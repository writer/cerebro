"""
Agent Audit Logging System

Provides structured audit logging for agent operations separate from provider audit events.
"""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import structlog
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from cerebro.agents.models import Base

logger = structlog.get_logger(__name__)


class AgentAuditEvent(Base):
    """
    Audit events for agent operations.

    Separate from core AuditEvent table which handles provider-generated audit logs.
    This table is org-scoped while AuditEvent is account-scoped.
    """

    __tablename__ = "agent_audit_events"

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
    session_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("agent_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Event details
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    agent_type: Mapped[str] = mapped_column(String(50), nullable=False)
    tool_name: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Target resource
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Timestamps
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    # Detailed event data
    event_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )

    # Performance tracking
    execution_time_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Result status
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


async def log_agent_event(
    org_id: UUID,
    session_id: UUID,
    event_type: str,
    actor: str,
    agent_type: str,
    tool_name: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    event_data: dict[str, Any] | None = None,
    execution_time_ms: float | None = None,
    success: bool = True,
    error_message: str | None = None,
) -> AgentAuditEvent:
    """
    Log an agent audit event to the database.

    Args:
        org_id: Organization ID
        session_id: Agent session ID
        event_type: Type of event (e.g., 'finding_status_changed')
        actor: User ID performing the action
        agent_type: Type of agent (e.g., 'security_analyst')
        tool_name: Name of tool invoked (optional)
        resource_type: Type of resource affected (optional)
        resource_id: ID of affected resource (optional)
        event_data: Additional event details as JSON (optional)
        execution_time_ms: Execution time in milliseconds (optional)
        success: Whether operation succeeded (default True)
        error_message: Error message if failed (optional)

    Returns:
        The created AgentAuditEvent
    """
    from cerebro.core.database import async_session_factory

    async with async_session_factory() as session:
        event = AgentAuditEvent(
            org_id=org_id,
            session_id=session_id,
            event_type=event_type,
            actor=actor,
            agent_type=agent_type,
            tool_name=tool_name,
            resource_type=resource_type,
            resource_id=resource_id,
            event_data=event_data or {},
            execution_time_ms=execution_time_ms,
            success=success,
            error_message=error_message,
        )

        session.add(event)
        await session.commit()
        await session.refresh(event)

        logger.info(
            "Agent audit event created",
            event_id=event.event_id,
            org_id=org_id,
            session_id=session_id,
            event_type=event_type,
            actor=actor,
            success=success,
        )

        return event


async def get_session_audit_trail(
    session_id: UUID,
    limit: int = 100,
    offset: int = 0,
) -> list[AgentAuditEvent]:
    """Get audit trail for a specific agent session."""
    from sqlalchemy import select

    from cerebro.core.database import async_session_factory

    async with async_session_factory() as session:
        query = (
            select(AgentAuditEvent)
            .where(AgentAuditEvent.session_id == session_id)
            .order_by(AgentAuditEvent.occurred_at.desc())
            .limit(limit)
            .offset(offset)
        )

        result = await session.execute(query)
        return list(result.scalars().all())


async def get_org_audit_trail(
    org_id: UUID,
    event_type: str | None = None,
    actor: str | None = None,
    resource_type: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AgentAuditEvent]:
    """Get filtered audit trail for an organization."""
    from sqlalchemy import and_, select

    from cerebro.core.database import async_session_factory

    async with async_session_factory() as session:
        conditions = [AgentAuditEvent.org_id == org_id]

        if event_type:
            conditions.append(AgentAuditEvent.event_type == event_type)
        if actor:
            conditions.append(AgentAuditEvent.actor == actor)
        if resource_type:
            conditions.append(AgentAuditEvent.resource_type == resource_type)
        if start_time:
            conditions.append(AgentAuditEvent.occurred_at >= start_time)
        if end_time:
            conditions.append(AgentAuditEvent.occurred_at <= end_time)

        query = (
            select(AgentAuditEvent)
            .where(and_(*conditions))
            .order_by(AgentAuditEvent.occurred_at.desc())
            .limit(limit)
            .offset(offset)
        )

        result = await session.execute(query)
        return list(result.scalars().all())
