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
from cerebro.integrations.sentinelone import (
    SentinelOneClient,
    SentinelOneConfig,
    SentinelOneIngestion,
)
from cerebro.integrations.state import IntegrationStateRepository

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
        return

    metadata_update: dict[str, Any] = {
        "last_status": status,
        "last_status_at": datetime.now(timezone.utc).isoformat(),
    }
    if payload:
        metadata_update["last_payload"] = payload
    if status == "error":
        error_value = payload.get("error") if isinstance(payload, dict) else None
        if error_value:
            metadata_update["last_error"] = str(error_value)
    if isinstance(payload, dict) and "last_sync_unix" in payload:
        try:
            sync_ts = datetime.fromtimestamp(
                float(payload["last_sync_unix"]), tz=timezone.utc
            )
        except Exception:  # pragma: no cover - defensive only
            sync_ts = None
        if sync_ts is not None:
            metadata_update["last_sync_unix"] = float(payload["last_sync_unix"])
            metadata_update["last_sync_at"] = sync_ts.isoformat()

    duration_seconds = (
        payload.get("duration_seconds") if isinstance(payload, dict) else None
    )
    if duration_seconds is not None:
        try:
            duration_value = float(duration_seconds)
        except (TypeError, ValueError):
            duration_value = None
        if duration_value is not None:
            metadata_update["last_duration_seconds"] = duration_value

    try:
        async with async_session_factory() as db:
            repo = IntegrationStateRepository(db)
            state = await repo.get_state(integration, scope or "default")
            existing_metadata = dict(state.state_metadata or {}) if state else {}

            if duration_seconds is not None:
                durations = list(existing_metadata.get("duration_samples", []))
                if duration_value is not None:
                    durations.append(duration_value)
                if len(durations) > 10:
                    durations = durations[-10:]
                metadata_update["duration_samples"] = durations

            if status == "ok":
                metadata_update["last_success_at"] = metadata_update.get(
                    "last_sync_at"
                ) or metadata_update.get("last_status_at")
            if status == "error":
                errors = list(existing_metadata.get("recent_errors", []))
                errors.append(
                    {
                        "recorded_at": metadata_update["last_status_at"],
                        "details": (
                            payload.get("error") if isinstance(payload, dict) else None
                        ),
                    }
                )
                if len(errors) > 10:
                    errors = errors[-10:]
                metadata_update["recent_errors"] = errors

            await repo.upsert_state(
                integration=integration,
                scope=scope or "default",
                metadata=metadata_update,
            )
            await db.commit()
    except Exception:  # pragma: no cover - metadata update should not break tasks
        logger.exception(
            "Failed to persist integration sync metadata for %%s", resource_id
        )


@celery_app.task(bind=True, name="cerebro.tasks.integration.sync_sentinelone")
def sync_sentinelone(self, lookback_minutes: Optional[int] = 30) -> Any:
    """Poll SentinelOne for recent activities and persist them as host events."""

    async def _run() -> Any:
        started_at = datetime.now(timezone.utc)
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
                "duration_seconds": (
                    datetime.now(timezone.utc) - started_at
                ).total_seconds(),
            }
            await _log_integration_sync(
                integration=integration_id,
                scope=integration_scope,
                status="error",
                payload=error_payload,
            )
            raise

        result.update({"status": "ok", "lookback_minutes": window})
        result["duration_seconds"] = (
            datetime.now(timezone.utc) - started_at
        ).total_seconds()
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
        started_at = datetime.now(timezone.utc)
        integration_scope = settings.kandji_org_name or "kandji"
        integration_id = "kandji.detections"
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
                error_payload = {
                    "status": "error",
                    "error": str(exc),
                    "duration_seconds": (
                        datetime.now(timezone.utc) - started_at
                    ).total_seconds(),
                }
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
        result["duration_seconds"] = (
            datetime.now(timezone.utc) - started_at
        ).total_seconds()
        await _log_integration_sync(
            integration=integration_id,
            scope=integration_scope,
            status="ok",
            payload=result,
        )
        return result

    return asyncio.run(_run())
