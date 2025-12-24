"""Analytics helpers for recording and querying agent runtime events."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from cerebro.agents.repositories import AgentAnalyticsRepository
from cerebro.core.config import settings


class AgentAnalyticsService:
    """Persist runtime analytics events for later analysis."""

    _RETENTION_PROBABILITY = 0.05
    _repository: AgentAnalyticsRepository = AgentAnalyticsRepository()

    @classmethod
    def configure_repository(cls, repository: AgentAnalyticsRepository) -> None:
        cls._repository = repository

    @classmethod
    async def record_event(
        cls,
        *,
        org_id: UUID,
        session_id: UUID,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        await cls._repository.insert_event(
            org_id=org_id,
            session_id=session_id,
            event_type=event_type,
            payload=payload,
        )

        retention_days = max(settings.agent_runtime_event_retention_days, 1)
        if random.random() < cls._RETENTION_PROBABILITY:
            cutoff = datetime.now(UTC) - timedelta(days=retention_days)
            await cls._repository.delete_older_than(cutoff)

    @classmethod
    async def list_events(
        cls,
        *,
        session_id: UUID,
        limit: int = 100,
        event_type: str | None = None,
        before: datetime | None = None,
        before_id: UUID | None = None,
    ) -> list[dict[str, Any]]:
        events = await cls._repository.list_events(
            session_id=session_id,
            limit=limit,
            event_type=event_type,
            before=before,
            before_id=before_id,
        )

        return [
            {
                "id": str(event.id),
                "event_type": event.event_type,
                "payload": event.payload,
                "created_at": event.created_at.isoformat(),
            }
            for event in events
        ]

    @classmethod
    async def summarize_events(
        cls,
        *,
        session_id: UUID,
        event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        result = await cls._repository.summarize_events(
            session_id=session_id,
            event_type=event_type,
        )

        summaries: list[dict[str, Any]] = []
        for row in result:
            summaries.append(
                {
                    "event_type": row.event_type,
                    "event_count": row.event_count,
                    "first_seen": (
                        row.first_seen.isoformat() if row.first_seen else None
                    ),
                    "last_seen": row.last_seen.isoformat() if row.last_seen else None,
                }
            )
        return summaries


async def list_session_events(
    *,
    session_id: UUID,
    limit: int = 100,
    event_type: str | None = None,
    before: datetime | None = None,
    before_id: UUID | None = None,
) -> list[dict[str, Any]]:
    """Module-level helper for retrieving runtime events."""

    return await AgentAnalyticsService.list_events(
        session_id=session_id,
        limit=limit,
        event_type=event_type,
        before=before,
        before_id=before_id,
    )
