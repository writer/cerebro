"""Utilities for persisting integration sync checkpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import IntegrationSyncState


class IntegrationStateRepository:
    """Lightweight repository for managing ``IntegrationSyncState`` rows."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_state(self, integration: str, scope: str = "default") -> Optional[IntegrationSyncState]:
        stmt = select(IntegrationSyncState).where(
            IntegrationSyncState.integration == integration,
            IntegrationSyncState.scope == scope,
        )
        return await self._session.scalar(stmt)

    async def upsert_state(
        self,
        *,
        integration: str,
        scope: str = "default",
        last_cursor: Optional[str] = None,
        last_timestamp: Optional[datetime] = None,
        metadata: Optional[dict[str, Any]] = None,
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
