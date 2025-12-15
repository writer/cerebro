"""Integration sync utilities for the Cerebro SDK."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, ClassVar, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.integrations.state import IntegrationStateRepository, IntegrationIssueEventRepository
from cerebro.core.models import IntegrationSyncState, IntegrationSyncIssueEvent
from cerebro.tasks.integration_tasks import sync_kandji, sync_sentinelone


@dataclass
class IntegrationStateRecord:
    integration: str
    scope: str
    last_cursor: Optional[str]
    last_timestamp: Optional[datetime]
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
    def get(cls, name: str) -> Optional[Callable[..., Any]]:
        return cls._tasks.get(name.lower())

    @classmethod
    def available(cls) -> dict[str, Callable[..., Any]]:
        return dict(cls._tasks)


class IntegrationService:
    """Facade for integration sync state and task orchestration."""

    def __init__(self, db: AsyncSession, *, registry: type[IntegrationTaskRegistry] | None = None) -> None:
        self._state_repo = IntegrationStateRepository(db)
        self._issue_repo = IntegrationIssueEventRepository(db)
        self._db = db
        self._registry = registry or IntegrationTaskRegistry

    async def list_states(self, *, integration: Optional[str] = None) -> list[IntegrationStateRecord]:
        states = await self._state_repo.list_states(integration=integration)
        return [self._state_to_record(state) for state in states]

    async def upsert_state(
        self,
        *,
        integration: str,
        scope: str = "default",
        last_cursor: Optional[str] = None,
        last_timestamp: Optional[datetime] = None,
        metadata: Optional[dict[str, Any]] = None,
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
        integration: Optional[str] = None,
        scope: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
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
        integration: Optional[str] = None,
        scope: Optional[str] = None,
        window: timedelta,
        bucket: timedelta,
    ) -> list[dict[str, Any]]:
        return await self._issue_repo.summarize_events(
            integration=integration,
            scope=scope,
            window=window,
            bucket=bucket,
        )

    def trigger_sync(self, integration: str, **kwargs) -> Optional[str]:
        task = self._registry.get(integration)
        if task is None:
            raise ValueError(f"Unknown integration '{integration}'")
        result = task.apply_async(kwargs=kwargs)
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
