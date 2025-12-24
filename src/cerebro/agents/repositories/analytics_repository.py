"""Data access helpers for agent runtime analytics."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Sequence
from uuid import UUID

from sqlalchemy import func, select, tuple_

from cerebro.agents.models import AgentRuntimeEvent
from cerebro.core.database import async_session_factory


class AgentAnalyticsRepository:
    """Encapsulates persistence and queries for runtime analytics events."""

    def __init__(self, session_factory=None) -> None:
        self._session_factory = session_factory or async_session_factory

    async def insert_event(
        self,
        *,
        org_id: UUID,
        session_id: UUID,
        event_type: str,
        payload: dict,
    ) -> AgentRuntimeEvent:
        async with self._session_factory() as db_session:
            event = AgentRuntimeEvent(
                org_id=org_id,
                session_id=session_id,
                event_type=event_type,
                payload=payload,
            )
            db_session.add(event)
            await db_session.commit()
            await db_session.refresh(event)
            return event

    async def delete_older_than(self, cutoff: datetime) -> None:
        async with self._session_factory() as db_session:
            await db_session.execute(
                AgentRuntimeEvent.__table__.delete().where(  # type: ignore[attr-defined]
                    AgentRuntimeEvent.created_at < cutoff
                )
            )
            await db_session.commit()

    async def list_events(
        self,
        *,
        session_id: UUID,
        limit: int,
        event_type: Optional[str],
        before: Optional[datetime],
        before_id: Optional[UUID],
    ) -> List[AgentRuntimeEvent]:
        async with self._session_factory() as db_session:
            stmt = (
                select(AgentRuntimeEvent)
                .where(AgentRuntimeEvent.session_id == session_id)
                .order_by(
                    AgentRuntimeEvent.created_at.desc(), AgentRuntimeEvent.id.desc()
                )
                .limit(limit)
            )

            if event_type:
                stmt = stmt.where(AgentRuntimeEvent.event_type == event_type)

            if before:
                if before_id:
                    stmt = stmt.where(AgentRuntimeEvent.id != before_id)
                    stmt = stmt.where(
                        tuple_(AgentRuntimeEvent.created_at, AgentRuntimeEvent.id)  # type: ignore[arg-type]
                        < tuple_(before, before_id)  # type: ignore[arg-type]
                    )
                else:
                    stmt = stmt.where(AgentRuntimeEvent.created_at < before)

            result = await db_session.execute(stmt)
            return list(result.scalars())

    async def summarize_events(
        self,
        *,
        session_id: UUID,
        event_type: Optional[str],
    ) -> Sequence:
        async with self._session_factory() as db_session:
            stmt = (
                select(
                    AgentRuntimeEvent.event_type,
                    func.count().label("event_count"),
                    func.min(AgentRuntimeEvent.created_at).label("first_seen"),
                    func.max(AgentRuntimeEvent.created_at).label("last_seen"),
                )
                .where(AgentRuntimeEvent.session_id == session_id)
                .group_by(AgentRuntimeEvent.event_type)
            )

            if event_type:
                stmt = stmt.where(AgentRuntimeEvent.event_type == event_type)

            result = await db_session.execute(stmt)
            return list(result.all())  # type: ignore[return-value]
