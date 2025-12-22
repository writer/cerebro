"""Session and memory helpers for the Cerebro SDK."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional
from uuid import UUID

from sqlalchemy import Select, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import (
    AgentMessage,
    AgentMemoryEntry,
    AgentSession,
    AgentType,
    MessageRole,
)

from cerebro_sdk.agents.base import AsyncManagerBase
from cerebro_sdk.agents.repositories import (
    join_filters,
    memory_scope_distribution,
    sqlite_scope_fallback,
)
from cerebro_sdk.agents.types import (
    AgentMessageRecord,
    AgentMemoryRecord,
    AgentMemoryStats,
    AgentNotFoundError,
    AgentSessionRecord,
    AgentValidationError,
)


class AgentManager(AsyncManagerBase):
    """Manage agent sessions, memory, and workflows via the SDK."""

    def __init__(self, db: AsyncSession) -> None:
        super().__init__(db)

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
            agent_type=self._coerce_enum(
                agent_type,
                AgentType,
                message=f"Invalid agent type '{agent_type}'",
            ),
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

    async def get_session(
        self, session_id: UUID, *, org_id: Optional[UUID] = None
    ) -> Optional[AgentSessionRecord]:
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
        count_stmt: Select = select(func.count(AgentSession.id)).where(
            AgentSession.org_id == org_id
        )

        if agent_type:
            try:
                agent_type_enum = self._coerce_enum(
                    agent_type,
                    AgentType,
                    message=f"Invalid agent type '{agent_type}'",
                )
            except AgentValidationError:
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
        role: str | MessageRole,
        content: dict[str, Any],
    ) -> AgentMessageRecord:
        session = await self._db.get(AgentSession, session_id)
        if not session:
            raise AgentNotFoundError(f"Session {session_id} not found")

        message = AgentMessage(
            session_id=session_id,
            role=self._coerce_enum(
                role,
                MessageRole,
                message=f"Invalid message role '{role}'",
            ),
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
                    scope_labels.append(
                        f"{scope_type}:{value}" if value else scope_type
                    )
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
            role_enum = self._coerce_enum(
                role,
                MessageRole,
                message=f"Invalid message role '{role}'",
            )
            filters.append(AgentMemoryEntry.role == role_enum)

        if scope_type:
            filters.append(AgentMemoryEntry.scopes.contains([{"type": scope_type}]))

        cutoff = None
        if since_hours is not None and since_hours > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
            filters.append(AgentMemoryEntry.created_at >= cutoff)

        where_clause = join_filters(filters)
        recent_reference = cutoff or (datetime.now(timezone.utc) - timedelta(hours=24))
        presented_expr = func.coalesce(
            AgentMemoryEntry.extra_metadata["presented_count"].as_integer(), 0
        )

        aggregate_stmt = select(
            func.count(AgentMemoryEntry.id).label("total"),
            func.sum(
                case((AgentMemoryEntry.created_at >= recent_reference, 1), else_=0)
            ).label("recent"),
            func.sum(case((presented_expr > 0, 1), else_=0)).label("presented"),
            func.coalesce(func.sum(AgentMemoryEntry.token_count), 0).label(
                "token_total"
            ),
            func.coalesce(func.avg(AgentMemoryEntry.decay_score), 0.0).label(
                "avg_decay"
            ),
        ).where(where_clause)

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
            (row[0].value if row[0] else "unknown").lower(): row[1] for row in role_rows
        }

        scope_distribution: dict[str, int] = {}
        dialect_name = getattr(getattr(self._db, "bind", None), "dialect", None)
        dialect_name = getattr(dialect_name, "name", None)
        if dialect_name == "postgresql":
            scope_rows = await self._db.execute(
                memory_scope_distribution(self._db, where_clause=where_clause)
            )
            scope_distribution = {
                row.scope_type.lower(): row.scope_count for row in scope_rows
            }
        else:
            scopes_to_process = await self._db.scalars(
                sqlite_scope_fallback(where_clause)
            )
            for scopes in scopes_to_process:
                for scope in scopes or []:
                    scope_name = (scope.get("type") or "unknown").lower()
                    scope_distribution[scope_name] = (
                        scope_distribution.get(scope_name, 0) + 1
                    )

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
                scope_type_value = scope.get("type")
                value = scope.get("value")
                if scope_type_value and scope_type_value != "session":
                    scope_labels.append(
                        f"{scope_type_value}:{value}" if value else scope_type_value
                    )
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
