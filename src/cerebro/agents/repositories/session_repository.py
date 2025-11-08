"""Database access helpers for agent sessions."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Tuple
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from cerebro.agents.models import (
    AgentMemoryEntry,
    AgentPolicySuggestion,
    AgentSession,
    AgentType,
    ToolInvocation,
)
from cerebro.core.database import async_session_factory


class AgentSessionRepository:
    """Encapsulates read/write operations for agent session data."""

    def __init__(self, session_factory=async_session_factory) -> None:
        self._session_factory = session_factory

    async def get_session(
        self,
        session_id: UUID,
        org_id: Optional[UUID] = None,
    ) -> Optional[AgentSession]:
        async with self._session_factory() as db_session:
            stmt = select(AgentSession).where(AgentSession.id == session_id)
            if org_id:
                stmt = stmt.where(AgentSession.org_id == org_id)

            result = await db_session.execute(stmt)
            return result.scalar_one_or_none()

    async def list_sessions(
        self,
        *,
        org_id: UUID,
        agent_type: Optional[AgentType] = None,
        created_by: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AgentSession], int]:
        filters: Sequence = [AgentSession.org_id == org_id]
        filters = list(filters)

        if agent_type is not None:
            filters.append(AgentSession.agent_type == agent_type)

        if created_by:
            filters.append(AgentSession.created_by == created_by)

        async with self._session_factory() as db_session:
            query = (
                select(AgentSession)
                .where(*filters)
                .order_by(AgentSession.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            sessions_result = await db_session.execute(query)
            sessions = list(sessions_result.scalars())

            count_stmt = select(func.count(AgentSession.id)).where(*filters)
            total_result = await db_session.execute(count_stmt)
            total = int(total_result.scalar_one())

        return sessions, total

    async def list_memory_entries(
        self,
        session_id: UUID,
        *,
        limit: Optional[int] = None,
    ) -> List[AgentMemoryEntry]:
        async with self._session_factory() as db_session:
            stmt = select(AgentMemoryEntry).where(AgentMemoryEntry.session_id == session_id)
            if limit is not None:
                stmt = stmt.order_by(AgentMemoryEntry.created_at.desc()).limit(limit)
            else:
                stmt = stmt.order_by(AgentMemoryEntry.created_at.desc())

            result = await db_session.execute(stmt)
            entries = list(result.scalars())

        return entries

    async def list_memory_entries_for_stats(
        self,
        session_id: UUID,
    ) -> List[AgentMemoryEntry]:
        return await self.list_memory_entries(session_id, limit=None)

    async def list_policy_suggestions(
        self,
        org_id: UUID,
        *,
        limit: int = 50,
    ) -> List[AgentPolicySuggestion]:
        async with self._session_factory() as db_session:
            stmt = (
                select(AgentPolicySuggestion)
                .where(AgentPolicySuggestion.org_id == org_id)
                .order_by(AgentPolicySuggestion.support_count.desc())
                .limit(limit)
            )
            result = await db_session.execute(stmt)
            return list(result.scalars())

    async def latest_tool_invocations(
        self,
        org_id: UUID,
        *,
        limit: int,
        tool_name: Optional[str] = None,
    ) -> List[Tuple[ToolInvocation, AgentSession]]:
        async with self._session_factory() as db_session:
            stmt = (
                select(ToolInvocation, AgentSession)
                .join(AgentSession, ToolInvocation.session_id == AgentSession.id)
                .where(AgentSession.org_id == org_id)
                .order_by(ToolInvocation.started_at.desc())
                .limit(limit)
            )
            if tool_name:
                stmt = stmt.where(ToolInvocation.tool_name == tool_name)

            result = await db_session.execute(stmt)
            return list(result.all())

    async def get_session_with_relations(
        self,
        session_id: UUID,
        *,
        org_id: Optional[UUID] = None,
    ) -> Optional[AgentSession]:
        async with self._session_factory() as db_session:
            stmt = (
                select(AgentSession)
                .options(selectinload(AgentSession.messages))
                .options(selectinload(AgentSession.tool_invocations))
                .where(AgentSession.id == session_id)
            )
            if org_id:
                stmt = stmt.where(AgentSession.org_id == org_id)

            result = await db_session.execute(stmt)
            return result.scalar_one_or_none()

    async def delete_session(
        self,
        *,
        session_id: UUID,
        org_id: UUID,
    ) -> bool:
        async with self._session_factory() as db_session:
            session = await db_session.get(AgentSession, session_id)
            if not session or session.org_id != org_id:
                return False

            await db_session.delete(session)
            await db_session.commit()
            return True

    async def save(self, objects: Iterable[object]) -> None:
        async with self._session_factory() as db_session:
            for obj in objects:
                db_session.add(obj)
            await db_session.commit()
