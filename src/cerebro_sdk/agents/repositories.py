"""Persistent access helpers used by SDK agent managers."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, Optional
from uuid import UUID

from sqlalchemy import Select, and_, func, literal, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import (
    AgentMemoryEntry,
    AgentPolicySuggestion,
    AgentReviewNotification,
    AgentReviewTicket,
    AgentSession,
    ToolApproval,
    ToolInvocation,
    ApprovalStatus,
    MessageRole,
    NotificationStatus,
    ToolInvocationStatus,
    TicketStatus,
)


class ToolingRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def list_invocations(
        self,
        *,
        session_id: Optional[UUID],
        org_id: Optional[UUID],
        status: Optional[ToolInvocationStatus],
        since: Optional[datetime],
        until: Optional[datetime],
        cursor: Optional[datetime],
        effective_limit: int,
        offset: int,
    ) -> list[ToolInvocation]:
        stmt = select(ToolInvocation)
        if org_id:
            stmt = stmt.join(AgentSession).where(AgentSession.org_id == org_id)
        if session_id:
            stmt = stmt.where(ToolInvocation.session_id == session_id)
        if status:
            stmt = stmt.where(ToolInvocation.status == status)
        if since:
            stmt = stmt.where(ToolInvocation.started_at >= since)
        if until:
            stmt = stmt.where(ToolInvocation.started_at <= until)
        if cursor:
            stmt = stmt.where(ToolInvocation.started_at < cursor)
        if offset:
            stmt = stmt.offset(offset)
        stmt = stmt.order_by(ToolInvocation.started_at.desc(), ToolInvocation.id.desc()).limit(effective_limit)
        return list(await self._db.scalars(stmt))

    async def list_approvals(
        self,
        *,
        org_id: UUID,
        status: Optional[ApprovalStatus],
        since: Optional[datetime],
        until: Optional[datetime],
        cursor: Optional[datetime],
        effective_limit: int,
        offset: int,
    ) -> list[ToolApproval]:
        stmt = select(ToolApproval).where(ToolApproval.org_id == org_id)
        if status:
            stmt = stmt.where(ToolApproval.status == status)
        if since:
            stmt = stmt.where(ToolApproval.requested_at >= since)
        if until:
            stmt = stmt.where(ToolApproval.requested_at <= until)
        if cursor:
            stmt = stmt.where(ToolApproval.requested_at < cursor)
        if offset:
            stmt = stmt.offset(offset)
        stmt = stmt.order_by(ToolApproval.requested_at.desc(), ToolApproval.id.desc()).limit(effective_limit)
        return list(await self._db.scalars(stmt))

    async def get_invocation(self, invocation_id: UUID) -> Optional[ToolInvocation]:
        return await self._db.get(ToolInvocation, invocation_id)

    async def get_approval(self, approval_id: UUID) -> Optional[ToolApproval]:
        return await self._db.get(ToolApproval, approval_id)


class NotificationRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def create(
        self,
        *,
        org_id: UUID,
        task_id: UUID,
        channel: str,
        payload: dict[str, object],
    ) -> AgentReviewNotification:
        notification = AgentReviewNotification(
            org_id=org_id,
            task_id=task_id,
            channel=channel,
            payload=payload,
            status=NotificationStatus.PENDING,
        )
        self._db.add(notification)
        await self._db.flush()
        return notification

    async def list(
        self,
        *,
        org_id: UUID,
        status: Optional[NotificationStatus],
        limit: int,
    ) -> list[AgentReviewNotification]:
        stmt = select(AgentReviewNotification).where(AgentReviewNotification.org_id == org_id)
        if status:
            stmt = stmt.where(AgentReviewNotification.status == status)
        stmt = stmt.order_by(AgentReviewNotification.created_at.desc()).limit(limit)
        return list(await self._db.scalars(stmt))

    async def get(self, notification_id: UUID) -> Optional[AgentReviewNotification]:
        return await self._db.get(AgentReviewNotification, notification_id)


class TicketRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def create(
        self,
        *,
        org_id: UUID,
        task_id: UUID,
        system: str,
        details: dict[str, object],
    ) -> AgentReviewTicket:
        ticket = AgentReviewTicket(
            org_id=org_id,
            task_id=task_id,
            system=system,
            details=details,
            status=TicketStatus.OPEN,
        )
        self._db.add(ticket)
        await self._db.flush()
        return ticket

    async def get(self, ticket_id: UUID) -> Optional[AgentReviewTicket]:
        return await self._db.get(AgentReviewTicket, ticket_id)

    async def list_for_task(self, task_id: UUID) -> list[AgentReviewTicket]:
        stmt = select(AgentReviewTicket).where(AgentReviewTicket.task_id == task_id)
        return list(await self._db.scalars(stmt))


def memory_scope_distribution(
    db: AsyncSession,
    *,
    where_clause,
) -> Select:
    scope_elements = func.jsonb_array_elements(AgentMemoryEntry.scopes).table_valued("scope").lateral()
    scope_json = scope_elements.column("scope")
    scope_type_col = scope_json["type"].astext
    return (
        select(
            func.coalesce(scope_type_col, literal("unknown")).label("scope_type"),
            func.count().label("scope_count"),
        )
        .select_from(AgentMemoryEntry)
        .join(scope_elements, true())
        .where(where_clause)
        .group_by(func.coalesce(scope_type_col, literal("unknown")))
    )


def sqlite_scope_fallback(where_clause) -> Select:
    return select(AgentMemoryEntry.scopes).where(where_clause)


def join_filters(filters: Iterable):
    filters = list(filters)
    if not filters:
        raise ValueError("filters must not be empty")
    return filters[0] if len(filters) == 1 else and_(*filters)
