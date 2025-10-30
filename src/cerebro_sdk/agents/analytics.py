"""Analytics helpers for Cerebro agent sessions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import AgentMessage, AgentRuntimeEvent, AgentSession

from cerebro_sdk.agents.base import AsyncManagerBase
from cerebro_sdk.agents.types import (
    AgentAnalyticsSummary,
    AgentEventRecord,
    AgentEventSummary,
)


class AgentAnalyticsClient(AsyncManagerBase):
    """Query agent runtime analytics events."""

    def __init__(self, db: AsyncSession) -> None:
        super().__init__(db)

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
