"""Celery tasks for third-party telemetry ingestion."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cerebro.core.config import settings
from cerebro.core.database import async_session_factory
from cerebro.integrations.kandji import KandjiClient, KandjiIngestion
from cerebro.integrations.sentinelone import SentinelOneClient, SentinelOneConfig, SentinelOneIngestion

from .celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="cerebro.tasks.integration.sync_sentinelone")
def sync_sentinelone(self, lookback_minutes: Optional[int] = 30) -> Any:
    """Poll SentinelOne for recent activities and persist them as host events."""

    async def _run() -> Any:
        if not settings.sentinelone_enabled:
            logger.info("SentinelOne integration disabled; skipping sync")
            return {"status": "disabled"}

        if not settings.sentinelone_api_base_url or not settings.sentinelone_api_token:
            logger.warning("SentinelOne credentials missing; skipping sync")
            return {"status": "skipped", "reason": "missing_credentials"}

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

        async with SentinelOneClient(config) as client:
            async with async_session_factory() as db:
                ingestion = SentinelOneIngestion(client)
                result = await ingestion.ingest(db, since=since)
        result.update({"status": "ok", "lookback_minutes": window})
        return result

    return asyncio.run(_run())


@celery_app.task(bind=True, name="cerebro.tasks.integration.sync_kandji")
def sync_kandji(self) -> Any:
    """Synchronize Kandji device inventory and vulnerability detections."""

    async def _run() -> Any:
        if not settings.kandji_enabled:
            logger.info("Kandji integration disabled; skipping sync")
            return {"status": "disabled"}

        if not settings.kandji_api_base_url or not settings.kandji_api_token:
            logger.warning("Kandji credentials missing; skipping sync")
            return {"status": "skipped", "reason": "missing_credentials"}

        async with KandjiClient(
            base_url=settings.kandji_api_base_url,
            api_token=settings.kandji_api_token,
            verify=settings.kandji_verify_tls,
        ) as client:
            async with async_session_factory() as db:
                ingestion = KandjiIngestion(
                    client,
                    organization=settings.kandji_org_name or "kandji",
                    site=settings.kandji_site,
                    agent_version="kandji-sync/1.0",
                )
                result = await ingestion.ingest(db)
        result.update({"status": "ok"})
        return result

    return asyncio.run(_run())
