"""Periodic health checks for integration syncs."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from cerebro.automation.integration_sync import (
    analyze_state,
    send_integration_sync_alert,
    should_suppress_issue,
)
from cerebro.core.config import settings
from cerebro.core.database import async_session_factory
from cerebro.integrations.state import IntegrationStateRepository

from .celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="cerebro.tasks.integration.monitor_sync_health")
def monitor_sync_health(self):
    async def _run():
        now = datetime.now(timezone.utc)
        issues_handled = 0

        async with async_session_factory() as db:
            repo = IntegrationStateRepository(db)
            states = await repo.list_states()

            for state in states:
                issue = analyze_state(state, now, settings.integration_sync_stale_seconds)
                if not issue:
                    continue

                metadata = state.state_metadata or {}
                if should_suppress_issue(
                    metadata,
                    issue,
                    now,
                    settings.integration_sync_alert_cooldown_seconds,
                ):
                    continue

                if settings.integration_sync_alert_webhook:
                    try:
                        await send_integration_sync_alert(
                            settings.integration_sync_alert_webhook,
                            issue,
                        )
                    except Exception:  # pragma: no cover - alert failures shouldn't stop monitoring
                        logger.exception(
                            "Failed to send integration sync alert for %s:%s",
                            issue.integration,
                            issue.scope,
                        )

                await repo.upsert_state(
                    integration=state.integration,
                    scope=state.scope,
                    metadata={
                        "last_alert_issue_type": issue.issue_type,
                        "last_alert_status": issue.status,
                        "last_alert_sent_at": now.isoformat(),
                    },
                )
                issues_handled += 1

            if issues_handled:
                await db.commit()

        if issues_handled:
            logger.warning("Integration sync health check surfaced %s issue(s)", issues_handled)
        return {"issues": issues_handled}

    return asyncio.run(_run())
