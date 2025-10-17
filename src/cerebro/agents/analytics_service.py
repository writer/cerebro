"""Analytics helpers for recording and querying agent runtime events."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import select

from cerebro.agents.models import AgentRuntimeEvent
from cerebro.core.config import settings
from cerebro.core.database import async_session_factory


async def _fetch_events(
    *,
    session_id: UUID,
    limit: int,
    event_type: Optional[str],
) -> List[Dict[str, Any]]:
    async with async_session_factory() as db_session:
        stmt = (
            select(AgentRuntimeEvent)
            .where(AgentRuntimeEvent.session_id == session_id)
            .order_by(AgentRuntimeEvent.created_at.desc())
            .limit(limit)
        )
        if event_type:
            stmt = stmt.where(AgentRuntimeEvent.event_type == event_type)
        result = await db_session.execute(stmt)
        events = result.scalars().all()

    return [
        {
            "id": str(event.id),
            "event_type": event.event_type,
            "payload": event.payload,
            "created_at": event.created_at.isoformat(),
        }
        for event in events
    ]


class AgentAnalyticsService:
    """Persist runtime analytics events for later analysis."""

    _RETENTION_PROBABILITY = 0.05

    @staticmethod
    async def record_event(
        *,
        org_id: UUID,
        session_id: UUID,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        async with async_session_factory() as db_session:
            event = AgentRuntimeEvent(
                org_id=org_id,
                session_id=session_id,
                event_type=event_type,
                payload=payload,
            )
            db_session.add(event)
            await db_session.commit()

        # Opportunistic retention pruning
        retention_days = max(settings.agent_runtime_event_retention_days, 1)
        if random.random() < AgentAnalyticsService._RETENTION_PROBABILITY:
            cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
            async with async_session_factory() as cleanup_session:
                await cleanup_session.execute(
                    AgentRuntimeEvent.__table__.delete().where(AgentRuntimeEvent.created_at < cutoff)
                )
                await cleanup_session.commit()

    @staticmethod
    async def list_events(
        *,
        session_id: UUID,
        limit: int = 100,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        return await _fetch_events(session_id=session_id, limit=limit, event_type=event_type)


async def list_session_events(
    *,
    session_id: UUID,
    limit: int = 100,
    event_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Module-level helper for retrieving runtime events."""

    return await _fetch_events(session_id=session_id, limit=limit, event_type=event_type)


# Maintain backwards compatibility for imports that capture the class before
# definition completes (e.g. during circular imports in tests).
AgentAnalyticsService.list_events = staticmethod(list_session_events)
