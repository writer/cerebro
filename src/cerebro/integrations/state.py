"""Utilities for persisting integration sync checkpoints."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.automation.integration_sync import IntegrationIssue
from cerebro.core.models import IntegrationSyncIssueEvent, IntegrationSyncState


def _normalize_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class IntegrationStateRepository:
    """Lightweight repository for managing ``IntegrationSyncState`` rows."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_state(
        self, integration: str, scope: str = "default"
    ) -> IntegrationSyncState | None:
        stmt = select(IntegrationSyncState).where(
            IntegrationSyncState.integration == integration,
            IntegrationSyncState.scope == scope,
        )
        return await self._session.scalar(stmt)

    async def list_states(
        self,
        *,
        integration: str | None = None,
    ) -> list[IntegrationSyncState]:
        stmt = select(IntegrationSyncState)
        if integration is not None:
            stmt = stmt.where(IntegrationSyncState.integration == integration)
        stmt = stmt.order_by(
            IntegrationSyncState.integration, IntegrationSyncState.scope
        )
        result = await self._session.scalars(stmt)
        return list(result)

    async def upsert_state(
        self,
        *,
        integration: str,
        scope: str = "default",
        last_cursor: str | None = None,
        last_timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IntegrationSyncState:
        state = await self.get_state(integration, scope)
        if state is None:
            state = IntegrationSyncState(
                integration=integration,
                scope=scope,
                last_cursor=last_cursor,
                last_timestamp=last_timestamp,
                state_metadata=metadata or {},
            )
            self._session.add(state)
        else:
            if last_cursor is not None:
                state.last_cursor = last_cursor
            if last_timestamp is not None:
                state.last_timestamp = last_timestamp
            if metadata:
                merged = dict(state.state_metadata or {})
                merged.update(metadata)
                state.state_metadata = merged
        await self._session.flush()
        return state


class IntegrationIssueEventRepository:
    """Repository handling persisted integration issue history."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record_issue_event(
        self, issue: IntegrationIssue
    ) -> IntegrationSyncIssueEvent:
        event = IntegrationSyncIssueEvent(
            integration=issue.integration,
            scope=issue.scope,
            issue_type=issue.issue_type,
            severity=issue.severity,
            message=issue.message,
            observed_at=_normalize_utc(issue.observed_at) or datetime.now(UTC),
            last_timestamp=_normalize_utc(issue.last_timestamp),
            age_seconds=issue.age_seconds,
            issue_metadata=dict(issue.metadata or {}),
        )
        self._session.add(event)
        await self._session.flush()
        return event

    async def list_events(
        self,
        *,
        integration: str | None = None,
        scope: str | None = None,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> list[IntegrationSyncIssueEvent]:
        stmt = select(IntegrationSyncIssueEvent)
        if integration is not None:
            stmt = stmt.where(IntegrationSyncIssueEvent.integration == integration)
        if scope is not None:
            stmt = stmt.where(IntegrationSyncIssueEvent.scope == scope)
        if since is not None:
            stmt = stmt.where(IntegrationSyncIssueEvent.observed_at >= since)
        stmt = stmt.order_by(desc(IntegrationSyncIssueEvent.observed_at))
        if limit is not None:
            stmt = stmt.limit(limit)
        result = await self._session.scalars(stmt)
        return list(result)

    async def summarize_events(
        self,
        *,
        integration: str | None = None,
        scope: str | None = None,
        window: timedelta,
        bucket: timedelta,
    ) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        since = now - window
        events = await self.list_events(
            integration=integration,
            scope=scope,
            since=since,
        )
        if not events:
            return []

        buckets: dict[datetime, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        bucket_seconds = max(int(bucket.total_seconds()), 1)

        for event in events:
            observed_at = _normalize_utc(event.observed_at)
            if observed_at is None:
                continue
            delta_seconds = int(max((observed_at - since).total_seconds(), 0))
            bucket_index = delta_seconds // bucket_seconds
            bucket_start = since + bucket * bucket_index
            bucket_start = bucket_start.replace(microsecond=0)
            severity_counts = buckets[bucket_start]
            severity_counts[event.severity] += 1

        response: list[dict[str, Any]] = []
        for bucket_start in sorted(buckets.keys()):
            response.append(
                {
                    "bucket_start": bucket_start,
                    "bucket_end": bucket_start + bucket,
                    "counts": dict(buckets[bucket_start]),
                }
            )
        return response
