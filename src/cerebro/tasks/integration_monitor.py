"""Periodic health checks for integration syncs."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from cerebro.automation.integration_sync import (
    analyze_state,
    send_integration_sync_alert,
    should_suppress_issue,
)
from cerebro.core.config import settings
from cerebro.core.database import async_session_factory
from cerebro.integrations.state import IntegrationStateRepository
from cerebro.tasks.integration_tasks import sync_kandji, sync_sentinelone

from .celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_retry_task(integration: str):
    if integration.startswith("kandji"):
        if not settings.kandji_enabled:
            return None, None
        return sync_kandji, {}
    if integration.startswith("sentinelone"):
        if not settings.sentinelone_enabled:
            return None, None
        kwargs: dict[str, Any] = {}
        if settings.integration_sync_retry_lookback_minutes:
            kwargs["lookback_minutes"] = settings.integration_sync_retry_lookback_minutes
        return sync_sentinelone, kwargs
    return None, None


def _maybe_queue_auto_retry(state, issue, now: datetime, metadata: dict[str, Any] | None) -> dict[str, Any]:
    if not settings.integration_sync_retry_enabled:
        return {}

    if issue.severity not in {"critical", "warning"}:
        return {}

    retry_task, retry_kwargs = _get_retry_task(state.integration)
    if retry_task is None:
        return {}

    last_retry_at_str = None
    if metadata:
        last_retry_at_str = metadata.get("last_auto_retry_at")

    last_retry_at = None
    if isinstance(last_retry_at_str, str):
        try:
            last_retry_at = datetime.fromisoformat(last_retry_at_str)
            if last_retry_at.tzinfo is None:
                last_retry_at = last_retry_at.replace(tzinfo=timezone.utc)
        except ValueError:
            last_retry_at = None

    if last_retry_at is not None:
        elapsed = (now - last_retry_at).total_seconds()
        if elapsed < settings.integration_sync_retry_cooldown_seconds:
            return {}

    try:
        result = retry_task.apply_async(kwargs=retry_kwargs or {})
        logger.info(
            "Queued automatic retry for integration %s scope %s (task %s)",
            state.integration,
            state.scope,
            result.id,
        )
        return {
            "last_auto_retry_at": now.isoformat(),
            "last_auto_retry_task_id": result.id,
        }
    except Exception:  # pragma: no cover - auto retry should not break monitoring
        logger.exception(
            "Failed to queue automatic retry for %s:%s",
            state.integration,
            state.scope,
        )
        return {}


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

                metadata_update = {
                    "last_alert_issue_type": issue.issue_type,
                    "last_alert_status": issue.status,
                    "last_alert_sent_at": now.isoformat(),
                }

                metadata_update.update(_maybe_queue_auto_retry(state, issue, now, metadata))

                await repo.upsert_state(
                    integration=state.integration,
                    scope=state.scope,
                    metadata=metadata_update,
                )
                issues_handled += 1

            if issues_handled:
                await db.commit()

        if issues_handled:
            logger.warning("Integration sync health check surfaced %s issue(s)", issues_handled)
        return {"issues": issues_handled}

    return asyncio.run(_run())
