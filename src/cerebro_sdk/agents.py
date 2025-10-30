"""Agent session, review, and analytics helpers for the Cerebro SDK."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional
from uuid import UUID

from sqlalchemy import Select, and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import (
    AgentMessage,
    AgentMemoryEntry,
    AgentPolicySuggestion,
    AgentReviewComment,
    AgentReviewHistory,
    AgentReviewNotification,
    AgentReviewTask,
    AgentReviewTicket,
    AgentRuntimeEvent,
    AgentSession,
    AgentType,
    ToolApproval,
    ToolInvocation,
    ToolInvocationStatus,
    ApprovalStatus,
    MessageRole,
    ReviewTaskStatus,
)


@dataclass(slots=True)
class AgentSessionRecord:
    session_id: UUID
    org_id: UUID
    agent_type: str
    created_at: datetime
    created_by: str
    title: Optional[str]
    is_active: bool
    context: dict[str, Any]


@dataclass(slots=True)
class AgentMessageRecord:
    message_id: UUID
    session_id: UUID
    role: str
    content: dict[str, Any]
    created_at: datetime


@dataclass(slots=True)
class AgentMemoryRecord:
    entry_id: UUID
    session_id: Optional[UUID]
    role: Optional[str]
    summary: Optional[str]
    decay_score: float
    last_accessed_at: datetime
    created_at: datetime
    scopes: list[dict[str, Any]]
    scope_labels: list[str]
    metadata: dict[str, Any]
    token_count: int
    content: Optional[str]


@dataclass(slots=True)
class AgentMemoryStats:
    total_entries: int
    recent_entries: int
    presented_entries: int
    average_decay: float
    token_total: int
    role_distribution: dict[str, int]
    scope_distribution: dict[str, int]
    top_memories: list[dict[str, Any]]


@dataclass(slots=True)
class AgentReviewTaskRecord:
    task_id: UUID
    session_id: UUID
    org_id: UUID
    status: str
    title: str
    summary: Optional[str]
    payload: dict[str, Any]
    promotion_target: Optional[str]
    priority: Optional[str]
    due_at: Optional[datetime]
    escalated_to: Optional[str]
    notification_channel: Optional[str]
    ticket_reference: Optional[str]
    created_by: str
    created_at: datetime
    resolved_by: Optional[str]
    resolved_at: Optional[datetime]
    resolution_notes: Optional[str]
    assigned_to: Optional[str]


@dataclass(slots=True)
class AgentReviewCommentRecord:
    comment_id: UUID
    task_id: UUID
    author: str
    content: str
    created_at: datetime
    metadata: dict[str, Any]


@dataclass(slots=True)
class AgentReviewHistoryRecord:
    history_id: UUID
    task_id: UUID
    changed_by: str
    change_type: str
    field_name: Optional[str]
    old_value: Optional[dict[str, Any]]
    new_value: Optional[dict[str, Any]]
    created_at: datetime
    metadata: dict[str, Any]


@dataclass(slots=True)
class AgentEventRecord:
    event_id: UUID
    session_id: UUID
    event_type: str
    payload: dict[str, Any]
    created_at: datetime


@dataclass(slots=True)
class AgentEventSummary:
    event_type: str
    event_count: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]


@dataclass(slots=True)
class AgentAnalyticsSummary:
    total_sessions: int
    active_sessions: int
    message_count: int
    event_count: int
    skill_tag_counts: dict[str, int]
    agent_type_counts: dict[str, int]


@dataclass(slots=True)
class ToolInvocationRecord:
    invocation_id: UUID
    session_id: UUID
    tool_name: str
    tool_version: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    input_data: dict[str, Any]
    output_data: Optional[dict[str, Any]]
    error_message: Optional[str]
    cel_policy_key: Optional[str]
    cel_expression: Optional[str]
    cel_result: Optional[bool]


@dataclass(slots=True)
class ToolApprovalRecord:
    approval_id: UUID
    org_id: UUID
    tool_invocation_id: UUID
    requested_by: str
    requested_at: datetime
    reason: str
    status: str
    decided_by: Optional[str]
    decided_at: Optional[datetime]
    decision_reason: Optional[str]
    expires_at: Optional[datetime]
    risk_assessment: dict[str, Any]


@dataclass(slots=True)
class AgentPolicySuggestionRecord:
    suggestion_id: UUID
    org_id: UUID
    tool_name: str
    cel_expression: str
    support_count: int
    reject_count: int
    details: dict[str, Any]
    last_seen: datetime
    created_at: datetime


@dataclass(slots=True)
class AgentNotificationRecord:
    notification_id: UUID
    task_id: UUID
    org_id: UUID
    channel: str
    status: str
    payload: dict[str, Any]
    created_at: datetime
    delivered_at: Optional[datetime]


@dataclass(slots=True)
class AgentTicketRecord:
    ticket_id: UUID
    task_id: UUID
    org_id: UUID
    system: str
    status: str
    details: dict[str, Any]
    external_id: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]


class AgentManager:
    """Manage agent sessions, memory, and workflows via the SDK."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def create_session(
        self,
        *,
        org_id: UUID,
        agent_type: AgentType | str,
        created_by: str,
        context: Optional[dict[str, Any]] = None,
        title: Optional[str] = None,
    ) -> AgentSessionRecord:
        session = AgentSession(
            org_id=org_id,
            agent_type=self._parse_agent_type(agent_type),
            created_by=created_by,
            title=title,
            context=dict(context or {}),
        )
        self._db.add(session)
        await self._db.commit()
        await self._db.refresh(session)
        return self._session_to_record(session)

    async def create_session_for_findings(
        self,
        *,
        org_id: UUID,
        created_by: str,
        finding_ids: Iterable[UUID | str],
        agent_type: AgentType | str = AgentType.SECURITY_ANALYST,
        title: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> AgentSessionRecord:
        finding_values = [str(fid) for fid in finding_ids]
        base_context = dict(context or {})
        existing = list(base_context.get("finding_ids", []))
        merged = sorted({*existing, *finding_values})
        base_context["finding_ids"] = merged
        return await self.create_session(
            org_id=org_id,
            agent_type=agent_type,
            created_by=created_by,
            context=base_context,
            title=title,
        )

    async def create_incident_session(
        self,
        *,
        org_id: UUID,
        created_by: str,
        incident_id: UUID | str,
        agent_type: AgentType | str = AgentType.INCIDENT_RESPONDER,
        title: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> AgentSessionRecord:
        base_context = dict(context or {})
        base_context["incident_id"] = str(incident_id)
        return await self.create_session(
            org_id=org_id,
            agent_type=agent_type,
            created_by=created_by,
            context=base_context,
            title=title,
        )

    async def get_session(self, session_id: UUID, *, org_id: Optional[UUID] = None) -> Optional[AgentSessionRecord]:
        session = await self._db.get(AgentSession, session_id)
        if not session:
            return None
        if org_id and session.org_id != org_id:
            return None
        return self._session_to_record(session)

    async def list_sessions(
        self,
        *,
        org_id: UUID,
        agent_type: AgentType | str | None = None,
        created_by: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AgentSessionRecord], int]:
        stmt = select(AgentSession).where(AgentSession.org_id == org_id)
        count_stmt: Select = select(func.count(AgentSession.id)).where(AgentSession.org_id == org_id)

        if agent_type:
            try:
                agent_type_enum = self._parse_agent_type(agent_type)
            except ValueError:
                return [], 0
            stmt = stmt.where(AgentSession.agent_type == agent_type_enum)
            count_stmt = count_stmt.where(AgentSession.agent_type == agent_type_enum)

        if created_by:
            stmt = stmt.where(AgentSession.created_by == created_by)
            count_stmt = count_stmt.where(AgentSession.created_by == created_by)

        stmt = stmt.order_by(AgentSession.created_at.desc()).offset(offset).limit(limit)

        sessions = list(await self._db.scalars(stmt))
        total = await self._db.scalar(count_stmt)
        total_count = int(total or 0)
        return [self._session_to_record(session) for session in sessions], total_count

    async def close_session(self, session_id: UUID) -> bool:
        session = await self._db.get(AgentSession, session_id)
        if not session:
            return False
        session.is_active = False
        await self._db.commit()
        return True

    async def add_message(
        self,
        *,
        session_id: UUID,
        role: str,
        content: dict[str, Any],
    ) -> AgentMessageRecord:
        session = await self._db.get(AgentSession, session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        message = AgentMessage(
            session_id=session_id,
            role=self._parse_message_role(role),
            content=content,
        )
        self._db.add(message)
        await self._db.commit()
        await self._db.refresh(message)
        return self._message_to_record(message)

    async def list_messages(
        self,
        *,
        session_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AgentMessageRecord]:
        stmt = (
            select(AgentMessage)
            .where(AgentMessage.session_id == session_id)
            .order_by(AgentMessage.created_at.asc())
            .offset(offset)
            .limit(limit)
        )
        rows = await self._db.scalars(stmt)
        return [self._message_to_record(row) for row in rows]

    async def delete_message(self, message_id: UUID) -> bool:
        message = await self._db.get(AgentMessage, message_id)
        if not message:
            return False
        await self._db.delete(message)
        await self._db.commit()
        return True

    async def list_memory_entries(
        self,
        *,
        session_id: UUID,
        limit: int = 50,
        include_content: bool = False,
    ) -> list[AgentMemoryRecord]:
        stmt = (
            select(AgentMemoryEntry)
            .where(AgentMemoryEntry.session_id == session_id)
            .order_by(AgentMemoryEntry.created_at.desc())
            .limit(limit)
        )
        entries = list(await self._db.scalars(stmt))
        records: list[AgentMemoryRecord] = []
        for entry in entries:
            scope_labels: list[str] = []
            for scope in entry.scopes or []:
                scope_type = scope.get("type")
                value = scope.get("value")
                if scope_type and scope_type != "session":
                    scope_labels.append(f"{scope_type}:{value}" if value else scope_type)
            records.append(
                AgentMemoryRecord(
                    entry_id=entry.id,
                    session_id=entry.session_id,
                    role=entry.role.value if entry.role else None,
                    summary=entry.summary,
                    decay_score=entry.decay_score,
                    last_accessed_at=entry.last_accessed_at,
                    created_at=entry.created_at,
                    scopes=list(entry.scopes or []),
                    scope_labels=scope_labels,
                    metadata=dict(entry.extra_metadata or {}),
                    token_count=entry.token_count or 0,
                    content=entry.content if include_content else None,
                )
            )
        return records

    async def get_memory_stats(
        self,
        *,
        session_id: UUID,
        role: MessageRole | str | None = None,
        scope_type: Optional[str] = None,
        since_hours: Optional[int] = None,
    ) -> Optional[AgentMemoryStats]:
        session = await self._db.get(AgentSession, session_id)
        if not session:
            return None

        filters: list[Any] = [AgentMemoryEntry.session_id == session_id]
        if role:
            role_enum = role if isinstance(role, MessageRole) else self._parse_message_role(role)
            filters.append(AgentMemoryEntry.role == role_enum)

        if scope_type:
            filters.append(AgentMemoryEntry.scopes.contains([{"type": scope_type}]))

        cutoff = None
        if since_hours is not None and since_hours > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
            filters.append(AgentMemoryEntry.created_at >= cutoff)

        where_clause = filters[0] if len(filters) == 1 else and_(*filters)

        recent_reference = cutoff or (datetime.now(timezone.utc) - timedelta(hours=24))
        presented_expr = func.coalesce(AgentMemoryEntry.extra_metadata["presented_count"].as_integer(), 0)

        aggregate_stmt = (
            select(
                func.count(AgentMemoryEntry.id).label("total"),
                func.sum(
                    case((AgentMemoryEntry.created_at >= recent_reference, 1), else_=0)
                ).label("recent"),
                func.sum(case((presented_expr > 0, 1), else_=0)).label("presented"),
                func.coalesce(func.sum(AgentMemoryEntry.token_count), 0).label("token_total"),
                func.coalesce(func.avg(AgentMemoryEntry.decay_score), 0.0).label("avg_decay"),
            )
            .where(where_clause)
        )

        aggregate = (await self._db.execute(aggregate_stmt)).first()
        if not aggregate or not aggregate.total:
            return AgentMemoryStats(
                total_entries=0,
                recent_entries=0,
                presented_entries=0,
                average_decay=0.0,
                token_total=0,
                role_distribution={},
                scope_distribution={},
                top_memories=[],
            )

        role_stmt = (
            select(AgentMemoryEntry.role, func.count())
            .where(where_clause)
            .group_by(AgentMemoryEntry.role)
        )
        role_rows = await self._db.execute(role_stmt)
        role_distribution = {
            (row[0].value if row[0] else "unknown").lower(): row[1]
            for row in role_rows
        }

        scopes_to_process = await self._db.scalars(
            select(AgentMemoryEntry.scopes)
            .where(where_clause)
            .limit(200)
        )
        scope_distribution: dict[str, int] = {}
        for scopes in scopes_to_process:
            for scope in scopes or []:
                scope_name = (scope.get("type") or "unknown").lower()
                scope_distribution[scope_name] = scope_distribution.get(scope_name, 0) + 1

        highlight_stmt = (
            select(
                AgentMemoryEntry.id,
                AgentMemoryEntry.summary,
                AgentMemoryEntry.decay_score,
                AgentMemoryEntry.last_accessed_at,
                AgentMemoryEntry.role,
                AgentMemoryEntry.scopes,
            )
            .where(where_clause)
            .order_by(AgentMemoryEntry.decay_score.desc())
            .limit(5)
        )
        highlight_rows = await self._db.execute(highlight_stmt)
        highlights: list[dict[str, Any]] = []
        for row in highlight_rows:
            _, summary, decay_score, last_accessed, role_value, scopes = row
            last_accessed = last_accessed or datetime.now(timezone.utc)
            if last_accessed.tzinfo is None:
                last_accessed = last_accessed.replace(tzinfo=timezone.utc)
            scope_labels: list[str] = []
            for scope in scopes or []:
                scope_type = scope.get("type")
                value = scope.get("value")
                if scope_type and scope_type != "session":
                    scope_labels.append(f"{scope_type}:{value}" if value else scope_type)
            highlights.append(
                {
                    "id": str(row[0]),
                    "summary": summary,
                    "decay_score": decay_score,
                    "last_accessed_at": last_accessed.isoformat(),
                    "role": role_value.value if role_value else None,
                    "scope_labels": scope_labels,
                }
            )

        return AgentMemoryStats(
            total_entries=int(aggregate.total or 0),
            recent_entries=int(aggregate.recent or 0),
            presented_entries=int(aggregate.presented or 0),
            average_decay=round(float(aggregate.avg_decay or 0.0), 3),
            token_total=int(aggregate.token_total or 0),
            role_distribution=role_distribution,
            scope_distribution=scope_distribution,
            top_memories=highlights,
        )

    async def link_findings(
        self,
        *,
        session_id: UUID,
        finding_ids: Iterable[UUID | str],
        regenerate: bool = False,
    ) -> Optional[AgentSessionRecord]:
        session = await self._db.get(AgentSession, session_id)
        if not session:
            return None
        context = dict(session.context or {})
        existing = set(str(fid) for fid in context.get("finding_ids", []))
        for fid in finding_ids:
            existing.add(str(fid))
        context["finding_ids"] = sorted(existing)
        session.context = context
        await self._db.commit()
        await self._db.refresh(session)

        if regenerate:
            from cerebro_sdk.findings import FindingService

            service = FindingService(self._db)
            await service.generate_for_org(session.org_id)

        return self._session_to_record(session)

    async def link_incident(
        self,
        *,
        session_id: UUID,
        incident_id: UUID | str,
    ) -> Optional[AgentSessionRecord]:
        session = await self._db.get(AgentSession, session_id)
        if not session:
            return None
        context = dict(session.context or {})
        context["incident_id"] = str(incident_id)
        session.context = context
        await self._db.commit()
        await self._db.refresh(session)
        return self._session_to_record(session)

    async def sessions_for_finding(
        self,
        *,
        org_id: UUID,
        finding_id: UUID | str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AgentSessionRecord]:
        target = str(finding_id)
        stmt = (
            select(AgentSession)
            .where(AgentSession.org_id == org_id)
            .where(AgentSession.context.contains({"finding_ids": [target]}))
            .order_by(AgentSession.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        sessions = list(await self._db.scalars(stmt))
        return [self._session_to_record(session) for session in sessions]

    async def sessions_for_incident(
        self,
        *,
        org_id: UUID,
        incident_id: UUID | str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AgentSessionRecord]:
        target = str(incident_id)
        incident_field = AgentSession.context["incident_id"].as_string()
        stmt = (
            select(AgentSession)
            .where(AgentSession.org_id == org_id)
            .where(incident_field == target)
            .order_by(AgentSession.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        sessions = list(await self._db.scalars(stmt))
        return [self._session_to_record(session) for session in sessions]

    @staticmethod
    def _parse_agent_type(agent_type: AgentType | str) -> AgentType:
        if isinstance(agent_type, AgentType):
            return agent_type
        try:
            return AgentType(agent_type)
        except ValueError as exc:
            raise ValueError(f"Invalid agent type '{agent_type}'") from exc

    @staticmethod
    def _parse_message_role(role: MessageRole | str) -> MessageRole:
        if isinstance(role, MessageRole):
            return role
        try:
            return MessageRole(role)
        except ValueError as exc:
            raise ValueError(f"Invalid message role '{role}'") from exc

    @staticmethod
    def _session_to_record(session: AgentSession) -> AgentSessionRecord:
        return AgentSessionRecord(
            session_id=session.id,
            org_id=session.org_id,
            agent_type=session.agent_type.value,
            created_at=session.created_at,
            created_by=session.created_by,
            title=session.title,
            is_active=session.is_active,
            context=dict(session.context or {}),
        )

    @staticmethod
    def _message_to_record(message: AgentMessage) -> AgentMessageRecord:
        return AgentMessageRecord(
            message_id=message.id,
            session_id=message.session_id,
            role=message.role.value,
            content=dict(message.content or {}),
            created_at=message.created_at,
        )


class AgentReviewManager:
    """Access and update the agent review queue."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    def _transaction(self):
        return self._db.begin_nested() if self._db.in_transaction() else self._db.begin()

    async def list_tasks(
        self,
        *,
        org_id: UUID,
        status: ReviewTaskStatus | str | None = None,
        limit: int = 50,
    ) -> list[AgentReviewTaskRecord]:
        stmt = select(AgentReviewTask).where(AgentReviewTask.org_id == org_id)
        if status:
            try:
                status_enum = status if isinstance(status, ReviewTaskStatus) else ReviewTaskStatus(status)
            except ValueError:
                return []
            stmt = stmt.where(AgentReviewTask.status == status_enum)
        stmt = stmt.order_by(AgentReviewTask.created_at.desc()).limit(limit)
        tasks = list(await self._db.scalars(stmt))
        return [self._to_record(task) for task in tasks]

    async def update_task_status(
        self,
        *,
        task_id: UUID,
        status: ReviewTaskStatus | str,
        resolved_by: str,
        notes: Optional[str] = None,
    ) -> Optional[AgentReviewTaskRecord]:
        task = await self._db.get(AgentReviewTask, task_id)
        if not task:
            return None
        try:
            status_enum = status if isinstance(status, ReviewTaskStatus) else ReviewTaskStatus(status)
        except ValueError as exc:
            raise ValueError("Invalid review task status") from exc

        async with self._transaction():
            old_status = task.status
            task.status = status_enum
            task.resolved_by = resolved_by
            task.resolved_at = datetime.now(timezone.utc)
            task.resolution_notes = notes
            await self._db.flush()

            await self._record_history(
                task_id=task.id,
                changed_by=resolved_by,
                change_type="status_change",
                field_name="status",
                old_value={"status": old_status.value},
                new_value={"status": status_enum.value},
                metadata={"notes": notes} if notes else {},
            )

        await self._db.refresh(task)
        return self._to_record(task)

    async def bulk_update(
        self,
        *,
        org_id: UUID,
        task_ids: Iterable[UUID],
        status: ReviewTaskStatus | str | None = None,
        resolved_by: Optional[str] = None,
        notes: Optional[str] = None,
        escalated_to: Optional[str] = None,
        due_at: Optional[datetime] = None,
        priority: Optional[str] = None,
        notification_channel: Optional[str] = None,
    ) -> list[AgentReviewTaskRecord]:
        ids = list(task_ids)
        if not ids:
            return []

        stmt = (
            select(AgentReviewTask)
            .where(AgentReviewTask.org_id == org_id)
            .where(AgentReviewTask.id.in_(ids))
        )
        tasks = list(await self._db.scalars(stmt))
        if not tasks:
            return []

        status_enum: Optional[ReviewTaskStatus] = None
        if status:
            try:
                status_enum = status if isinstance(status, ReviewTaskStatus) else ReviewTaskStatus(status)
            except ValueError as exc:
                raise ValueError("Invalid review task status") from exc

        async with self._transaction():
            for task in tasks:
                if priority:
                    task.priority = priority
                if due_at:
                    task.due_at = due_at
                if notification_channel:
                    task.notification_channel = notification_channel
                if escalated_to:
                    task.escalated_to = escalated_to
                if status_enum:
                    old_status = task.status
                    task.status = status_enum
                    task.resolved_by = resolved_by
                    task.resolved_at = datetime.now(timezone.utc)
                    task.resolution_notes = notes
                    await self._db.flush()
                    await self._record_history(
                        task_id=task.id,
                        changed_by=resolved_by or "system",
                        change_type="status_change",
                        field_name="status",
                        old_value={"status": old_status.value},
                        new_value={"status": status_enum.value},
                        metadata={"notes": notes} if notes else {},
                    )

        for task in tasks:
            await self._db.refresh(task)
        return [self._to_record(task) for task in tasks]

    async def assign_task(
        self,
        *,
        task_id: UUID,
        assigned_to: str,
        assigned_by: str,
    ) -> Optional[AgentReviewTaskRecord]:
        task = await self._db.get(AgentReviewTask, task_id)
        if not task:
            return None
        now = datetime.now(timezone.utc)
        async with self._transaction():
            task.assigned_to = assigned_to
            task.assigned_by = assigned_by
            task.assigned_at = now
            await self._db.flush()
            await self._record_history(
                task_id=task.id,
                changed_by=assigned_by,
                change_type="assignment",
                field_name="assigned_to",
                old_value=None,
                new_value={"assigned_to": assigned_to},
                metadata={},
            )
        await self._db.refresh(task)
        return self._to_record(task)

    async def add_comment(
        self,
        *,
        task_id: UUID,
        author: str,
        content: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> AgentReviewCommentRecord:
        async with self._transaction():
            comment = AgentReviewComment(
                task_id=task_id,
                author=author,
                content=content,
                extra_metadata=dict(metadata or {}),
            )
            self._db.add(comment)
            await self._db.flush()
            await self._record_history(
                task_id=task_id,
                changed_by=author,
                change_type="comment",
                field_name="comments",
                old_value=None,
                new_value={"comment_id": str(comment.id)},
                metadata=dict(metadata or {}),
            )

        await self._db.refresh(comment)
        return self._comment_to_record(comment)

    async def list_comments(self, *, task_id: UUID) -> list[AgentReviewCommentRecord]:
        stmt = (
            select(AgentReviewComment)
            .where(AgentReviewComment.task_id == task_id)
            .order_by(AgentReviewComment.created_at.asc())
        )
        comments = list(await self._db.scalars(stmt))
        return [self._comment_to_record(comment) for comment in comments]

    async def list_history(self, *, task_id: UUID, limit: int = 100) -> list[AgentReviewHistoryRecord]:
        stmt = (
            select(AgentReviewHistory)
            .where(AgentReviewHistory.task_id == task_id)
            .order_by(AgentReviewHistory.created_at.desc())
            .limit(limit)
        )
        history_items = list(await self._db.scalars(stmt))
        return [self._history_to_record(item) for item in history_items]

    async def _record_history(
        self,
        *,
        task_id: UUID,
        changed_by: str,
        change_type: str,
        field_name: Optional[str],
        old_value: Optional[dict[str, Any]],
        new_value: Optional[dict[str, Any]],
        metadata: dict[str, Any],
    ) -> None:
        history = AgentReviewHistory(
            task_id=task_id,
            changed_by=changed_by,
            change_type=change_type,
            field_name=field_name,
            old_value=old_value,
            new_value=new_value,
            extra_metadata=metadata,
        )
        self._db.add(history)

    @staticmethod
    def _to_record(task: AgentReviewTask) -> AgentReviewTaskRecord:
        return AgentReviewTaskRecord(
            task_id=task.id,
            session_id=task.session_id,
            org_id=task.org_id,
            status=task.status.value,
            title=task.title,
            summary=task.summary,
            payload=dict(task.payload or {}),
            promotion_target=task.promotion_target,
            priority=task.priority,
            due_at=task.due_at,
            escalated_to=task.escalated_to,
            notification_channel=task.notification_channel,
            ticket_reference=task.ticket_reference,
            created_by=task.created_by,
            created_at=task.created_at,
            resolved_by=task.resolved_by,
            resolved_at=task.resolved_at,
            resolution_notes=task.resolution_notes,
            assigned_to=task.assigned_to,
        )

    @staticmethod
    def _comment_to_record(comment: AgentReviewComment) -> AgentReviewCommentRecord:
        return AgentReviewCommentRecord(
            comment_id=comment.id,
            task_id=comment.task_id,
            author=comment.author,
            content=comment.content,
            created_at=comment.created_at,
            metadata=dict(comment.extra_metadata or {}),
        )

    @staticmethod
    def _history_to_record(item: AgentReviewHistory) -> AgentReviewHistoryRecord:
        return AgentReviewHistoryRecord(
            history_id=item.id,
            task_id=item.task_id,
            changed_by=item.changed_by,
            change_type=item.change_type,
            field_name=item.field_name,
            old_value=dict(item.old_value or {}) if item.old_value else None,
            new_value=dict(item.new_value or {}) if item.new_value else None,
            created_at=item.created_at,
            metadata=dict(item.extra_metadata or {}),
        )


class AgentAnalyticsClient:
    """Query agent runtime analytics events."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def list_events(
        self,
        *,
        session_id: UUID,
        limit: int = 100,
        event_type: Optional[str] = None,
    ) -> list[AgentEventRecord]:
        stmt = (
            select(AgentRuntimeEvent)
            .where(AgentRuntimeEvent.session_id == session_id)
            .order_by(AgentRuntimeEvent.created_at.desc())
            .limit(limit)
        )
        if event_type:
            stmt = stmt.where(AgentRuntimeEvent.event_type == event_type)
        events = list(await self._db.scalars(stmt))
        return [
            AgentEventRecord(
                event_id=event.id,
                session_id=event.session_id,
                event_type=event.event_type,
                payload=dict(event.payload or {}),
                created_at=event.created_at,
            )
            for event in events
        ]

    async def summarize_events(
        self,
        *,
        session_id: UUID,
        event_type: Optional[str] = None,
    ) -> list[AgentEventSummary]:
        stmt = (
            select(
                AgentRuntimeEvent.event_type,
                func.count().label("event_count"),
                func.min(AgentRuntimeEvent.created_at),
                func.max(AgentRuntimeEvent.created_at),
            )
            .where(AgentRuntimeEvent.session_id == session_id)
            .group_by(AgentRuntimeEvent.event_type)
        )
        if event_type:
            stmt = stmt.where(AgentRuntimeEvent.event_type == event_type)
        result = await self._db.execute(stmt)
        summaries: list[AgentEventSummary] = []
        for row in result:
            summaries.append(
                AgentEventSummary(
                    event_type=row.event_type,
                    event_count=row.event_count,
                    first_seen=row[2],
                    last_seen=row[3],
                )
            )
        return summaries

    async def summarize_org(
        self,
        *,
        org_id: UUID,
        window_hours: int = 24,
    ) -> AgentAnalyticsSummary:
        window_start = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        sessions = list(
            await self._db.scalars(
                select(AgentSession)
                .where(AgentSession.org_id == org_id)
                .where(AgentSession.created_at >= window_start)
            )
        )
        session_ids = [session.id for session in sessions]

        message_count = 0
        event_count = 0
        if session_ids:
            message_result = await self._db.execute(
                select(AgentMessage.session_id, func.count())
                .where(AgentMessage.session_id.in_(session_ids))
                .group_by(AgentMessage.session_id)
            )
            for _, count in message_result:
                message_count += count

            event_result = await self._db.execute(
                select(AgentRuntimeEvent.session_id, func.count())
                .where(AgentRuntimeEvent.session_id.in_(session_ids))
                .group_by(AgentRuntimeEvent.session_id)
            )
            for _, count in event_result:
                event_count += count

        skill_tag_counts: dict[str, int] = {}
        agent_type_counts: dict[str, int] = {}
        for session in sessions:
            agent_type_counts.setdefault(session.agent_type.value, 0)
            agent_type_counts[session.agent_type.value] += 1

            context = session.context or {}
            skill_tags = context.get("_skill_tags") or []
            for tag in skill_tags:
                skill_tag_counts.setdefault(tag, 0)
                skill_tag_counts[tag] += 1

        return AgentAnalyticsSummary(
            total_sessions=len(sessions),
            active_sessions=sum(1 for session in sessions if session.is_active),
            message_count=message_count,
            event_count=event_count,
            skill_tag_counts=skill_tag_counts,
            agent_type_counts=agent_type_counts,
        )


class AgentToolingManager:
    """Inspect and manage tool invocations and approvals."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    def _transaction(self):
        return self._db.begin_nested() if self._db.in_transaction() else self._db.begin()

    async def list_invocations(
        self,
        *,
        session_id: Optional[UUID] = None,
        org_id: Optional[UUID] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ToolInvocationRecord]:
        stmt = select(ToolInvocation)
        if org_id:
            stmt = stmt.join(AgentSession).where(AgentSession.org_id == org_id)
        if session_id:
            stmt = stmt.where(ToolInvocation.session_id == session_id)
        if status:
            try:
                status_enum = ToolInvocationStatus(status)
            except ValueError:
                return []
            stmt = stmt.where(ToolInvocation.status == status_enum)
        stmt = stmt.order_by(ToolInvocation.started_at.desc()).offset(offset).limit(limit)
        invocations = list(await self._db.scalars(stmt))
        return [self._invocation_to_record(invocation) for invocation in invocations]

    async def get_invocation(self, invocation_id: UUID) -> Optional[ToolInvocationRecord]:
        invocation = await self._db.get(ToolInvocation, invocation_id)
        if not invocation:
            return None
        return self._invocation_to_record(invocation)

    async def list_approvals(
        self,
        *,
        org_id: UUID,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ToolApprovalRecord]:
        stmt = select(ToolApproval).where(ToolApproval.org_id == org_id)
        if status:
            try:
                status_enum = ApprovalStatus(status)
            except ValueError:
                return []
            stmt = stmt.where(ToolApproval.status == status_enum)
        stmt = stmt.order_by(ToolApproval.requested_at.desc()).offset(offset).limit(limit)
        approvals = list(await self._db.scalars(stmt))
        return [self._approval_to_record(approval) for approval in approvals]

    async def update_approval_status(
        self,
        *,
        approval_id: UUID,
        status: str,
        decided_by: str,
        decision_reason: Optional[str] = None,
    ) -> Optional[ToolApprovalRecord]:
        approval = await self._db.get(ToolApproval, approval_id)
        if not approval:
            return None
        try:
            status_enum = ApprovalStatus(status)
        except ValueError as exc:
            raise ValueError("Invalid approval status") from exc

        invocation = approval.tool_invocation
        now = datetime.now(timezone.utc)

        async with self._transaction():
            approval.status = status_enum
            approval.decided_by = decided_by
            approval.decided_at = now
            approval.decision_reason = decision_reason

            if invocation:
                if status_enum == ApprovalStatus.APPROVED:
                    invocation.status = ToolInvocationStatus.SUCCESS
                    invocation.completed_at = now
                elif status_enum == ApprovalStatus.REJECTED:
                    invocation.status = ToolInvocationStatus.ERROR
                    invocation.error_message = decision_reason or "Rejected by reviewer"
                    invocation.completed_at = now

        await self._db.refresh(approval)
        if invocation:
            await self._db.refresh(invocation)
        return self._approval_to_record(approval)

    async def list_policy_suggestions(
        self,
        *,
        org_id: UUID,
        tool_name: Optional[str] = None,
    ) -> list[AgentPolicySuggestionRecord]:
        stmt = select(AgentPolicySuggestion).where(AgentPolicySuggestion.org_id == org_id)
        if tool_name:
            stmt = stmt.where(AgentPolicySuggestion.tool_name == tool_name)
        stmt = stmt.order_by(AgentPolicySuggestion.last_seen.desc())
        suggestions = list(await self._db.scalars(stmt))
        return [self._policy_to_record(suggestion) for suggestion in suggestions]

    @staticmethod
    def _invocation_to_record(invocation: ToolInvocation) -> ToolInvocationRecord:
        input_payload = invocation.input_data if isinstance(invocation.input_data, dict) else {"value": invocation.input_data}
        output_payload = None
        if invocation.output_data is not None:
            output_payload = invocation.output_data if isinstance(invocation.output_data, dict) else {"value": invocation.output_data}
        return ToolInvocationRecord(
            invocation_id=invocation.id,
            session_id=invocation.session_id,
            tool_name=invocation.tool_name,
            tool_version=invocation.tool_version,
            status=invocation.status.value,
            started_at=invocation.started_at,
            completed_at=invocation.completed_at,
            input_data=input_payload,
            output_data=output_payload,
            error_message=invocation.error_message,
            cel_policy_key=invocation.cel_policy_key,
            cel_expression=invocation.cel_expression,
            cel_result=invocation.cel_result,
        )

    @staticmethod
    def _approval_to_record(approval: ToolApproval) -> ToolApprovalRecord:
        return ToolApprovalRecord(
            approval_id=approval.id,
            org_id=approval.org_id,
            tool_invocation_id=approval.tool_invocation_id,
            requested_by=approval.requested_by,
            requested_at=approval.requested_at,
            reason=approval.reason,
            status=approval.status.value,
            decided_by=approval.decided_by,
            decided_at=approval.decided_at,
            decision_reason=approval.decision_reason,
            expires_at=approval.expires_at,
            risk_assessment=approval.risk_assessment if isinstance(approval.risk_assessment, dict) else {},
        )

    @staticmethod
    def _policy_to_record(suggestion: AgentPolicySuggestion) -> AgentPolicySuggestionRecord:
        return AgentPolicySuggestionRecord(
            suggestion_id=suggestion.id,
            org_id=suggestion.org_id,
            tool_name=suggestion.tool_name,
            cel_expression=suggestion.cel_expression,
            support_count=suggestion.support_count,
            reject_count=suggestion.reject_count,
            details=suggestion.details if isinstance(suggestion.details, dict) else {},
            last_seen=suggestion.last_seen,
            created_at=suggestion.created_at,
        )


class AgentNotificationManager:
    """Manage notification and ticket records for agent workflows."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    def _transaction(self):
        return self._db.begin_nested() if self._db.in_transaction() else self._db.begin()

    async def enqueue_notification(
        self,
        *,
        org_id: UUID,
        task_id: UUID,
        channel: str,
        payload: Optional[dict[str, Any]] = None,
    ) -> AgentNotificationRecord:
        async with self._transaction():
            notification = AgentReviewNotification(
                org_id=org_id,
                task_id=task_id,
                channel=channel,
                payload=dict(payload or {}),
                status="pending",
            )
            self._db.add(notification)
        await self._db.refresh(notification)
        return self._notification_to_record(notification)

    async def list_notifications(
        self,
        *,
        org_id: UUID,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> list[AgentNotificationRecord]:
        stmt = select(AgentReviewNotification).where(AgentReviewNotification.org_id == org_id)
        if status:
            stmt = stmt.where(AgentReviewNotification.status == status)
        stmt = stmt.order_by(AgentReviewNotification.created_at.desc()).limit(limit)
        notifications = list(await self._db.scalars(stmt))
        return [self._notification_to_record(notification) for notification in notifications]

    async def mark_delivered(self, notification_id: UUID) -> Optional[AgentNotificationRecord]:
        notification = await self._db.get(AgentReviewNotification, notification_id)
        if not notification:
            return None
        async with self._transaction():
            notification.status = "delivered"
            notification.delivered_at = datetime.now(timezone.utc)
        await self._db.refresh(notification)
        return self._notification_to_record(notification)

    async def create_ticket(
        self,
        *,
        org_id: UUID,
        task_id: UUID,
        system: str,
        summary: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> AgentTicketRecord:
        details = dict(metadata or {})
        details.setdefault("summary", summary)
        async with self._transaction():
            ticket = AgentReviewTicket(
                org_id=org_id,
                task_id=task_id,
                system=system,
                details=details,
                status="open",
            )
            self._db.add(ticket)
        await self._db.refresh(ticket)
        return self._ticket_to_record(ticket)

    async def close_ticket(
        self,
        *,
        ticket_id: UUID,
        external_id: Optional[str] = None,
    ) -> Optional[AgentTicketRecord]:
        ticket = await self._db.get(AgentReviewTicket, ticket_id)
        if not ticket:
            return None
        async with self._transaction():
            ticket.status = "closed"
            ticket.updated_at = datetime.now(timezone.utc)
            if external_id:
                ticket.external_id = external_id
        await self._db.refresh(ticket)
        return self._ticket_to_record(ticket)

    async def list_tickets(self, *, task_id: UUID) -> list[AgentTicketRecord]:
        stmt = select(AgentReviewTicket).where(AgentReviewTicket.task_id == task_id)
        tickets = list(await self._db.scalars(stmt))
        return [self._ticket_to_record(ticket) for ticket in tickets]

    @staticmethod
    def _notification_to_record(notification: AgentReviewNotification) -> AgentNotificationRecord:
        return AgentNotificationRecord(
            notification_id=notification.id,
            task_id=notification.task_id,
            org_id=notification.org_id,
            channel=notification.channel,
            status=notification.status,
            payload=dict(notification.payload or {}),
            created_at=notification.created_at,
            delivered_at=notification.delivered_at,
        )

    @staticmethod
    def _ticket_to_record(ticket: AgentReviewTicket) -> AgentTicketRecord:
        return AgentTicketRecord(
            ticket_id=ticket.id,
            task_id=ticket.task_id,
            org_id=ticket.org_id,
            system=ticket.system,
            status=ticket.status,
            details=dict(ticket.details or {}),
            external_id=ticket.external_id,
            created_at=ticket.created_at,
            updated_at=ticket.updated_at,
        )


class AgentPlaybook:
    """High-level helpers orchestrating common agent playbooks."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    def _transaction(self):
        return self._db.begin_nested() if self._db.in_transaction() else self._db.begin()

    async def start_incident_playbook(
        self,
        *,
        org_id: UUID,
        created_by: str,
        incident_id: UUID | str,
        finding_ids: Optional[Iterable[UUID | str]] = None,
        title: Optional[str] = None,
    ) -> AgentSessionRecord:
        manager = AgentManager(self._db)
        session = await manager.create_incident_session(
            org_id=org_id,
            created_by=created_by,
            incident_id=incident_id,
            title=title,
        )
        if finding_ids:
            await manager.link_findings(session_id=session.session_id, finding_ids=finding_ids)
            session = await manager.get_session(session.session_id)
            if session is None:
                raise RuntimeError("Failed to refresh session after linking findings")
        return session

    async def kickoff_findings_playbook(
        self,
        *,
        org_id: UUID,
        created_by: str,
        finding_ids: Iterable[UUID | str],
        title: Optional[str] = None,
    ) -> AgentSessionRecord:
        manager = AgentManager(self._db)
        return await manager.create_session_for_findings(
            org_id=org_id,
            created_by=created_by,
            finding_ids=finding_ids,
            title=title,
        )

    async def memory_snapshot(self, session_id: UUID) -> Optional[AgentMemoryStats]:
        manager = AgentManager(self._db)
        return await manager.get_memory_stats(session_id=session_id)

    async def schedule_notifications(
        self,
        *,
        task_id: UUID,
        channels: Iterable[str],
    ) -> list[AgentNotificationRecord]:
        task = await self._db.get(AgentReviewTask, task_id)
        if not task:
            return []
        notification_manager = AgentNotificationManager(self._db)
        results: list[AgentNotificationRecord] = []
        for channel in channels:
            record = await notification_manager.enqueue_notification(
                org_id=task.org_id,
                task_id=task_id,
                channel=channel,
            )
            results.append(record)
        return results

    async def escalate_to_ticket(
        self,
        *,
        task_id: UUID,
        system: str,
        summary: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Optional[AgentTicketRecord]:
        task = await self._db.get(AgentReviewTask, task_id)
        if not task:
            return None
        notification_manager = AgentNotificationManager(self._db)
        return await notification_manager.create_ticket(
            org_id=task.org_id,
            task_id=task_id,
            system=system,
            summary=summary,
            metadata=metadata,
        )

    async def record_policy_suggestion(
        self,
        *,
        org_id: UUID,
        tool_name: str,
        cel_expression: str,
        support_delta: int = 1,
        reject_delta: int = 0,
        details: Optional[dict[str, Any]] = None,
    ) -> AgentPolicySuggestionRecord:
        now = datetime.now(timezone.utc)
        stmt = select(AgentPolicySuggestion).where(
            AgentPolicySuggestion.org_id == org_id,
            AgentPolicySuggestion.tool_name == tool_name,
            AgentPolicySuggestion.cel_expression == cel_expression,
        )
        existing = await self._db.scalar(stmt)
        if existing:
            async with self._transaction():
                existing.support_count += support_delta
                existing.reject_count += reject_delta
                existing.details.update(details or {})
                existing.last_seen = now
            await self._db.refresh(existing)
            return AgentToolingManager._policy_to_record(existing)

        async with self._transaction():
            suggestion = AgentPolicySuggestion(
                org_id=org_id,
                tool_name=tool_name,
                cel_expression=cel_expression,
                support_count=support_delta,
                reject_count=reject_delta,
                details=dict(details or {}),
                last_seen=now,
                created_at=now,
            )
            self._db.add(suggestion)
        await self._db.refresh(suggestion)
        return AgentToolingManager._policy_to_record(suggestion)
