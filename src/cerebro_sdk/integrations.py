"""Integration sync utilities for the Cerebro SDK."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, ClassVar

from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import IntegrationSyncIssueEvent, IntegrationSyncState
from cerebro.integrations.state import (
    IntegrationIssueEventRepository,
    IntegrationStateRepository,
)
from cerebro.tasks.integration_tasks import sync_kandji, sync_sentinelone


@dataclass
class IntegrationStateRecord:
    integration: str
    scope: str
    last_cursor: str | None
    last_timestamp: datetime | None
    metadata: dict[str, Any]


@dataclass
class IntegrationIssueRecord:
    integration: str
    scope: str
    severity: str
    issue_type: str
    message: str
    observed_at: datetime
    metadata: dict[str, Any]


class IntegrationTaskRegistry:
    """Pluggable registry for integration task entrypoints."""

    _tasks: ClassVar[dict[str, Callable[..., Any]]] = {}

    @classmethod
    def register(cls, name: str, task: Callable[..., Any]) -> None:
        cls._tasks[name.lower()] = task

    @classmethod
    def unregister(cls, name: str) -> None:
        cls._tasks.pop(name.lower(), None)

    @classmethod
    def get(cls, name: str) -> Callable[..., Any] | None:
        return cls._tasks.get(name.lower())

    @classmethod
    def available(cls) -> dict[str, Callable[..., Any]]:
        return dict(cls._tasks)


class IntegrationService:
    """Facade for integration sync state and task orchestration."""

    def __init__(
        self, db: AsyncSession, *, registry: type[IntegrationTaskRegistry] | None = None
    ) -> None:
        self._state_repo = IntegrationStateRepository(db)
        self._issue_repo = IntegrationIssueEventRepository(db)
        self._db = db
        self._registry = registry or IntegrationTaskRegistry

    async def list_states(
        self, *, integration: str | None = None
    ) -> list[IntegrationStateRecord]:
        states = await self._state_repo.list_states(integration=integration)
        return [self._state_to_record(state) for state in states]

    async def upsert_state(
        self,
        *,
        integration: str,
        scope: str = "default",
        last_cursor: str | None = None,
        last_timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IntegrationStateRecord:
        async with self._db.begin():
            state = await self._state_repo.upsert_state(
                integration=integration,
                scope=scope,
                last_cursor=last_cursor,
                last_timestamp=last_timestamp,
                metadata=metadata,
            )
        return self._state_to_record(state)

    async def list_issue_events(
        self,
        *,
        integration: str | None = None,
        scope: str | None = None,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> list[IntegrationIssueRecord]:
        events = await self._issue_repo.list_events(
            integration=integration,
            scope=scope,
            since=since,
            limit=limit,
        )
        return [self._issue_to_record(event) for event in events]

    async def summarize_issue_events(
        self,
        *,
        integration: str | None = None,
        scope: str | None = None,
        window: timedelta,
        bucket: timedelta,
    ) -> list[dict[str, Any]]:
        return await self._issue_repo.summarize_events(
            integration=integration,
            scope=scope,
            window=window,
            bucket=bucket,
        )

    def trigger_sync(self, integration: str, **kwargs) -> str | None:
        task = self._registry.get(integration)
        if task is None:
            raise ValueError(f"Unknown integration '{integration}'")
        result = task.apply_async(kwargs=kwargs)  # type: ignore[attr-defined]
        return result.id

    @staticmethod
    def _state_to_record(state: IntegrationSyncState) -> IntegrationStateRecord:
        return IntegrationStateRecord(
            integration=state.integration,
            scope=state.scope,
            last_cursor=state.last_cursor,
            last_timestamp=state.last_timestamp,
            metadata=dict(state.state_metadata or {}),
        )

    @staticmethod
    def _issue_to_record(event: IntegrationSyncIssueEvent) -> IntegrationIssueRecord:
        return IntegrationIssueRecord(
            integration=event.integration,
            scope=event.scope,
            severity=event.severity,
            issue_type=event.issue_type,
            message=event.message,
            observed_at=event.observed_at,
            metadata=dict(event.issue_metadata or {}),
        )


# Register default integration tasks
IntegrationTaskRegistry.register("kandji", sync_kandji)
IntegrationTaskRegistry.register("sentinelone", sync_sentinelone)
