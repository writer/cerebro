"""Periodic tasks for Serval ticket synchronization."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from dateutil import parser as date_parser

from cerebro.core.database import async_session_factory
from cerebro.integrations.serval_service import ServalIntegrationRepository
from cerebro.integrations.serval_ticket_service import ServalTicketService
from cerebro.integrations.state import IntegrationStateRepository

from .celery_app import celery_app

logger = logging.getLogger(__name__)


def _parse_timestamp(payload: dict[str, object]) -> Optional[datetime]:
    """Extract a timezone-aware timestamp from common Serval ticket fields."""
    for key in ("updatedAt", "completedAt", "escalatedAt", "createdAt"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            try:
                dt = date_parser.isoparse(value)
            except (ValueError, TypeError):
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
    return None


@celery_app.task(bind=True, name="cerebro.tasks.integration.sync_serval_tickets")
def sync_serval_tickets(self) -> dict[str, object]:
    """Synchronize Serval ticket changes back into Cerebro."""

    async def _run() -> dict[str, object]:
        """Execute the sync in an async context so the Celery task stays synchronous."""
        processed = 0
        updated = 0
        async with async_session_factory() as db:
            repo = ServalIntegrationRepository(db)
            integrations = await repo.list_all()
            if not integrations:
                return {"processed": 0, "updated": 0}

            state_repo = IntegrationStateRepository(db)
            service = ServalTicketService(db)

            for settings in integrations:
                scope = str(settings.org_id)
                state = await state_repo.get_state("serval.tickets", scope)
                since = state.last_timestamp if state else None
                tickets = await service.list_recent_tickets(settings.org_id, since)
                latest_timestamp = since
                org_updates = 0

                for payload in tickets:
                    processed += 1
                    ts = _parse_timestamp(payload)
                    status_change = await service.synchronize_remote_ticket(
                        org_id=settings.org_id,
                        ticket_payload=payload,
                    )
                    if status_change is not None:
                        org_updates += 1
                        updated += 1
                    if ts is not None and (latest_timestamp is None or ts > latest_timestamp):
                        latest_timestamp = ts

                # Persist cursor metadata so subsequent runs only fetch incremental changes.
                await state_repo.upsert_state(
                    integration="serval.tickets",
                    scope=scope,
                    last_timestamp=latest_timestamp,
                    metadata={
                        "last_sync_count": len(tickets),
                        "updated_statuses": org_updates,
                        "synced_at": datetime.now(timezone.utc).isoformat(),
                    },
                )

            await db.commit()
        return {"processed": processed, "updated": updated}

    return asyncio.run(_run())


__all__ = ["sync_serval_tickets"]
