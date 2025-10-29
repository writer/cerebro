"""Agent session, review, and analytics helpers for the Cerebro SDK."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import (
    AgentMessage,
    AgentMemoryEntry,
    AgentReviewComment,
    AgentReviewHistory,
    AgentReviewTask,
    AgentRuntimeEvent,
    AgentSession,
    AgentType,
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


class AgentManager:
    """Manage agent sessions, memory, and workflows via the SDK."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def create_session(
        self,
        *,
        org_id: UUID,
        agent_type: str,
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
        agent_type: str = "security_analyst",
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
        agent_type: str = "incident_responder",
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
        agent_type: Optional[str] = None,
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

    async def get_memory_stats(self, *, session_id: UUID) -> Optional[AgentMemoryStats]:
        session = await self._db.get(AgentSession, session_id)
        if not session:
            return None

        entries = list(
            await self._db.scalars(select(AgentMemoryEntry).where(AgentMemoryEntry.session_id == session_id))
        )
        if not entries:
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

        role_distribution: dict[str, int] = {}
        scope_distribution: dict[str, int] = {}
        token_total = 0
        decay_sum = 0.0
        recent_entries = 0
        presented_entries = 0
        highlights: list[dict[str, Any]] = []
        recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

        for entry in entries:
            created_at = entry.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            last_accessed = entry.last_accessed_at
            if last_accessed.tzinfo is None:
                last_accessed = last_accessed.replace(tzinfo=timezone.utc)

            role_key = (entry.role.value if entry.role else "unknown").lower()
            role_distribution[role_key] = role_distribution.get(role_key, 0) + 1

            for scope in entry.scopes or []:
                scope_type = (scope.get("type") or "unknown").lower()
                scope_distribution[scope_type] = scope_distribution.get(scope_type, 0) + 1

            metadata = entry.extra_metadata or {}
            if int(metadata.get("presented_count", 0) or 0) > 0:
                presented_entries += 1

            if created_at >= recent_cutoff:
                recent_entries += 1

            token_total += entry.token_count or 0
            decay_sum += entry.decay_score

            scope_labels: list[str] = []
            for scope in entry.scopes or []:
                scope_type = scope.get("type")
                value = scope.get("value")
                if scope_type and scope_type != "session":
                    scope_labels.append(f"{scope_type}:{value}" if value else scope_type)

            highlights.append(
                {
                    "id": str(entry.id),
                    "summary": entry.summary,
                    "decay_score": entry.decay_score,
                    "last_accessed_at": last_accessed.isoformat(),
                    "role": entry.role.value if entry.role else None,
                    "scope_labels": scope_labels,
                }
            )

        highlights.sort(key=lambda item: item["decay_score"], reverse=True)
        average_decay = decay_sum / len(entries)

        return AgentMemoryStats(
            total_entries=len(entries),
            recent_entries=recent_entries,
            presented_entries=presented_entries,
            average_decay=round(average_decay, 3),
            token_total=token_total,
            role_distribution=role_distribution,
            scope_distribution=scope_distribution,
            top_memories=highlights[:5],
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
    ) -> list[AgentSessionRecord]:
        sessions = list(await self._db.scalars(select(AgentSession).where(AgentSession.org_id == org_id)))
        target = str(finding_id)
        matched: list[AgentSessionRecord] = []
        for session in sessions:
            context = session.context or {}
            ids = [str(value) for value in context.get("finding_ids", [])]
            if target in ids:
                matched.append(self._session_to_record(session))
        return matched

    async def sessions_for_incident(
        self,
        *,
        org_id: UUID,
        incident_id: UUID | str,
    ) -> list[AgentSessionRecord]:
        sessions = list(await self._db.scalars(select(AgentSession).where(AgentSession.org_id == org_id)))
        target = str(incident_id)
        return [
            self._session_to_record(session)
            for session in sessions
            if str((session.context or {}).get("incident_id")) == target
        ]

    @staticmethod
    def _parse_agent_type(agent_type: str) -> AgentType:
        try:
            return AgentType(agent_type)
        except ValueError as exc:
            raise ValueError(f"Invalid agent type '{agent_type}'") from exc

    @staticmethod
    def _parse_message_role(role: str) -> MessageRole:
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

    async def list_tasks(
        self,
        *,
        org_id: UUID,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> list[AgentReviewTaskRecord]:
        stmt = select(AgentReviewTask).where(AgentReviewTask.org_id == org_id)
        if status:
            try:
                status_enum = ReviewTaskStatus(status)
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
        status: str,
        resolved_by: str,
        notes: Optional[str] = None,
    ) -> Optional[AgentReviewTaskRecord]:
        task = await self._db.get(AgentReviewTask, task_id)
        if not task:
            return None
        try:
            status_enum = ReviewTaskStatus(status)
        except ValueError as exc:
            raise ValueError("Invalid review task status") from exc

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

        await self._db.commit()
        await self._db.refresh(task)
        return self._to_record(task)

    async def bulk_update(
        self,
        *,
        org_id: UUID,
        task_ids: Iterable[UUID],
        status: Optional[str] = None,
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
                status_enum = ReviewTaskStatus(status)
            except ValueError as exc:
                raise ValueError("Invalid review task status") from exc

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
                await self._record_history(
                    task_id=task.id,
                    changed_by=resolved_by or "system",
                    change_type="status_change",
                    field_name="status",
                    old_value={"status": old_status.value},
                    new_value={"status": status_enum.value},
                    metadata={"notes": notes} if notes else {},
                )

        await self._db.commit()
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
        task.assigned_to = assigned_to
        task.assigned_by = assigned_by
        task.assigned_at = now
        await self._record_history(
            task_id=task.id,
            changed_by=assigned_by,
            change_type="assignment",
            field_name="assigned_to",
            old_value=None,
            new_value={"assigned_to": assigned_to},
            metadata={},
        )
        await self._db.commit()
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
        comment = AgentReviewComment(
            task_id=task_id,
            author=author,
            content=content,
            extra_metadata=dict(metadata or {}),
        )
        self._db.add(comment)
        await self._db.commit()
        await self._db.refresh(comment)
        await self._record_history(
            task_id=task_id,
            changed_by=author,
            change_type="comment",
            field_name="comments",
            old_value=None,
            new_value={"comment_id": str(comment.id)},
            metadata=dict(metadata or {}),
        )
        await self._db.commit()
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
        await self._db.flush()

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
