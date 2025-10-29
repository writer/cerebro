"""Celery tasks for third-party telemetry ingestion."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cerebro.auditability.transparency_log import get_transparency_log, LogEntryType
from cerebro.core.config import settings
from cerebro.core.database import async_session_factory
from cerebro.integrations.kandji import KandjiClient, KandjiIngestion
from cerebro.integrations.sentinelone import SentinelOneClient, SentinelOneConfig, SentinelOneIngestion

from .celery_app import celery_app

logger = logging.getLogger(__name__)


async def _log_integration_sync(
    *,
    integration: str,
    scope: Optional[str],
    status: str,
    payload: dict[str, Any],
) -> None:
    """Append integration sync results to the transparency log."""

    try:
        details = {
            "integration": integration,
            "scope": scope or "default",
            "status": status,
            **payload,
        }
        resource_id = f"{integration}:{scope or 'default'}"
        transparency_log = get_transparency_log()
        await transparency_log.append_entry(
            LogEntryType.INTEGRATION_SYNC,
            actor="system",
            resource_id=resource_id,
            action="integration.sync",
            details=details,
        )
    except Exception:  # pragma: no cover - logging must not break tasks
        logger.exception("Failed to append integration sync audit entry")


@celery_app.task(bind=True, name="cerebro.tasks.integration.sync_sentinelone")
def sync_sentinelone(self, lookback_minutes: Optional[int] = 30) -> Any:
    """Poll SentinelOne for recent activities and persist them as host events."""

    async def _run() -> Any:
        integration_scope = settings.sentinelone_org_name or "sentinelone"
        integration_id = "sentinelone.activities"
        if not settings.sentinelone_enabled:
            logger.info("SentinelOne integration disabled; skipping sync")
            payload = {"status": "disabled"}
            await _log_integration_sync(
                integration=integration_id,
                scope=integration_scope,
                status="disabled",
                payload=payload,
            )
            return payload

        if not settings.sentinelone_api_base_url or not settings.sentinelone_api_token:
            logger.warning("SentinelOne credentials missing; skipping sync")
            payload = {"status": "skipped", "reason": "missing_credentials"}
            await _log_integration_sync(
                integration=integration_id,
                scope=integration_scope,
                status="skipped",
                payload=payload,
            )
            return payload

        # Apply a defensive default window so recurring schedules can omit an
        # explicit lookback while still bounding the API request size.
        window = lookback_minutes if lookback_minutes and lookback_minutes > 0 else 30
        since = datetime.now(timezone.utc) - timedelta(minutes=window)

        config = SentinelOneConfig(
            base_url=settings.sentinelone_api_base_url,
            api_token=settings.sentinelone_api_token,
            organization=settings.sentinelone_org_name or "sentinelone",
            site=settings.sentinelone_site,
            agent_version="sentinelone-sync/1.0",
            verify=settings.sentinelone_verify_tls,
        )

        try:
            async with SentinelOneClient(config) as client:
                async with async_session_factory() as db:
                    ingestion = SentinelOneIngestion(client)
                    result = await ingestion.ingest(db, since=since)
        except Exception as exc:
            error_payload = {
                "status": "error",
                "error": str(exc),
                "lookback_minutes": window,
            }
            await _log_integration_sync(
                integration=integration_id,
                scope=integration_scope,
                status="error",
                payload=error_payload,
            )
            raise

        result.update({"status": "ok", "lookback_minutes": window})
        await _log_integration_sync(
            integration=integration_id,
            scope=integration_scope,
            status="ok",
            payload=result,
        )
        return result

    return asyncio.run(_run())


@celery_app.task(bind=True, name="cerebro.tasks.integration.sync_kandji")
def sync_kandji(self) -> Any:
    """Synchronize Kandji device inventory and vulnerability detections."""

    async def _run() -> Any:
        integration_scope = settings.kandji_org_name or "kandji"
        integration_id = _DETECTIONS_SCOPE
        if not settings.kandji_enabled:
            logger.info("Kandji integration disabled; skipping sync")
            payload = {"status": "disabled"}
            await _log_integration_sync(
                integration=integration_id,
                scope=integration_scope,
                status="disabled",
                payload=payload,
            )
            return payload

        if not settings.kandji_api_base_url or not settings.kandji_api_token:
            logger.warning("Kandji credentials missing; skipping sync")
            payload = {"status": "skipped", "reason": "missing_credentials"}
            await _log_integration_sync(
                integration=integration_id,
                scope=integration_scope,
                status="skipped",
                payload=payload,
            )
            return payload

        async with KandjiClient(
            base_url=settings.kandji_api_base_url,
            api_token=settings.kandji_api_token,
            verify=settings.kandji_verify_tls,
        ) as client:
            try:
                async with async_session_factory() as db:
                    ingestion = KandjiIngestion(
                        client,
                        organization=integration_scope,
                        site=settings.kandji_site,
                        agent_version="kandji-sync/1.0",
                    )
                    result = await ingestion.ingest(db)
            except Exception as exc:
                error_payload = {"status": "error", "error": str(exc)}
                await _log_integration_sync(
                    integration=integration_id,
                    scope=integration_scope,
                    status="error",
                    payload=error_payload,
                )
                raise
        # ``ingest`` returns high-level counters which we bubble up so task
        # monitoring dashboards can surface progress without parsing logs.
        result.update({"status": "ok"})
        await _log_integration_sync(
            integration=integration_id,
            scope=integration_scope,
            status="ok",
            payload=result,
        )
        return result

    return asyncio.run(_run())
