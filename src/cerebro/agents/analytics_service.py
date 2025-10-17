"""Analytics helpers for recording and querying agent runtime events."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from uuid import UUID

from sqlalchemy import select

from cerebro.agents.models import AgentRuntimeEvent
from cerebro.core.config import settings
from cerebro.core.database import async_session_factory


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
    ) -> List[Dict[str, Any]]:
        async with async_session_factory() as db_session:
            stmt = (
                select(AgentRuntimeEvent)
                .where(AgentRuntimeEvent.session_id == session_id)
                .order_by(AgentRuntimeEvent.created_at.desc())
                .limit(limit)
            )
            result = await db_session.execute(stmt)
            events = result.scalars().all()

        serialized: List[Dict[str, Any]] = []
        for event in events:
            serialized.append(
                {
                    "id": str(event.id),
                    "event_type": event.event_type,
                    "payload": event.payload,
                    "created_at": event.created_at.isoformat(),
                }
            )
        return serialized
