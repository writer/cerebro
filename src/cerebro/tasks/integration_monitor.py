"""Periodic health checks for integration syncs."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from cerebro.automation.integration_sync import (
    analyze_state,
    send_integration_sync_alert,
    should_suppress_issue,
)
from cerebro.core.config import settings
from cerebro.core.database import async_session_factory
from cerebro.integrations.coverage import summarize_integration_coverage
from cerebro.integrations.state import (
    IntegrationIssueEventRepository,
    IntegrationStateRepository,
)
from cerebro.tasks.integration_tasks import sync_kandji, sync_sentinelone

from .celery_app import celery_app

logger = structlog.get_logger(__name__)


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
            kwargs["lookback_minutes"] = (
                settings.integration_sync_retry_lookback_minutes
            )
        return sync_sentinelone, kwargs
    return None, None


def _maybe_queue_auto_retry(
    state, issue, now: datetime, metadata: dict[str, Any] | None
) -> dict[str, Any]:
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
                last_retry_at = last_retry_at.replace(tzinfo=UTC)
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


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    except (ValueError, TypeError):
        return None


def _determine_coverage_severity(summary: dict[str, Any]) -> str | None:
    ratio = summary.get("coverage_ratio")
    status = summary.get("status")

    warning_threshold = getattr(settings, "integration_coverage_warning_threshold", 0.7)
    critical_threshold = getattr(
        settings, "integration_coverage_critical_threshold", 0.4
    )

    if status in {"critical", "missing"}:
        return "critical"
    if status == "warning":
        return "warning"
    if ratio is None:
        return None
    if ratio < critical_threshold:
        return "critical"
    if ratio < warning_threshold:
        return "warning"
    return None


async def _send_coverage_alert(
    webhook_url: str, summary: dict[str, Any], severity: str
) -> None:
    integration = summary.get("integration", "unknown")
    scopes = summary.get("scopes", {})
    healthy = scopes.get("healthy", 0)
    total = scopes.get("total", 0)
    ratio = summary.get("coverage_ratio")
    ratio_pct = f"{ratio * 100:.1f}%" if isinstance(ratio, (int, float)) else "N/A"
    providers = ", ".join(summary.get("providers", [])) or "n/a"
    evaluated_at = summary.get("evaluated_at")
    evaluated_str = (
        evaluated_at.isoformat()
        if isinstance(evaluated_at, datetime)
        else str(evaluated_at)
    )

    color = "#d32f2f" if severity == "critical" else "#f57c00"

    payload = {
        "text": (
            f"Integration coverage {severity.upper()} for {integration}: "
            f"{healthy}/{total} scopes healthy ({ratio_pct})."
        ),
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{integration} coverage {severity.upper()}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Healthy scopes:* {healthy}/{total}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Coverage ratio:* {ratio_pct}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Providers:* {providers}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Status:* {summary.get('status')}",
                            },
                        ],
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": (
                                    f"Last success: {summary.get('last_success') or 'n/a'} • "
                                    f"Evaluated: {evaluated_str}"
                                ),
                            }
                        ],
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "View /api/v1/integrations/coverage for complete details.",
                            }
                        ],
                    },
                ],
            }
        ],
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(webhook_url, json=payload)
        response.raise_for_status()


@celery_app.task(bind=True, name="cerebro.tasks.integration.monitor_sync_health")
def monitor_sync_health(self):
    async def _run():
        now = datetime.now(UTC)
        issues_handled = 0

        async with async_session_factory() as db:
            repo = IntegrationStateRepository(db)
            issue_repo = IntegrationIssueEventRepository(db)
            states = await repo.list_states()

            for state in states:
                issue = analyze_state(
                    state, now, settings.integration_sync_stale_seconds
                )
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
                    except (
                        Exception
                    ):  # pragma: no cover - alert failures shouldn't stop monitoring
                        logger.exception(
                            "Failed to send integration sync alert for %s:%s",
                            issue.integration,
                            issue.scope,
                        )

                await issue_repo.record_issue_event(issue)

                metadata_update = {
                    "last_alert_issue_type": issue.issue_type,
                    "last_alert_status": issue.status,
                    "last_alert_sent_at": now.isoformat(),
                }

                metadata_update.update(
                    _maybe_queue_auto_retry(state, issue, now, metadata)
                )

                await repo.upsert_state(
                    integration=state.integration,
                    scope=state.scope,
                    metadata=metadata_update,
                )
                issues_handled += 1

            coverage_alerts = 0

            webhook_url = (
                settings.integration_coverage_alert_webhook
                or settings.integration_sync_alert_webhook
            )

            if webhook_url:
                coverage_summaries = await summarize_integration_coverage(
                    db,
                    stale_seconds=settings.integration_sync_stale_seconds,
                )

                for summary in coverage_summaries:
                    severity = _determine_coverage_severity(summary)
                    if not severity:
                        continue

                    integration = summary.get("integration")
                    if not integration:
                        continue

                    coverage_state = await repo.get_state(integration, "__coverage__")
                    metadata = (coverage_state.state_metadata if coverage_state else {}) or {}  # type: ignore[assignment]
                    last_status = (metadata or {}).get("last_coverage_status")
                    last_alert_severity = (metadata or {}).get(
                        "last_coverage_alert_status"
                    )
                    last_alert_at = _parse_iso_datetime(
                        (metadata or {}).get("last_coverage_alert_at")
                    )

                    cooldown_seconds = getattr(
                        settings,
                        "integration_sync_alert_cooldown_seconds",
                        1800,
                    )

                    if (
                        last_status == summary.get("status")
                        and last_alert_severity == severity
                        and last_alert_at
                        and (now - last_alert_at) < timedelta(seconds=cooldown_seconds)
                    ):
                        continue

                    try:
                        await _send_coverage_alert(webhook_url, summary, severity)
                        coverage_alerts += 1
                    except httpx.HTTPError:
                        logger.exception(
                            "integration_coverage_alert_failed: integration=%s, severity=%s",
                            integration,
                            severity,
                        )

                    metadata_update = {  # type: ignore[assignment]
                        "last_coverage_status": str(summary.get("status") or ""),
                        "last_coverage_ratio": str(summary.get("coverage_ratio") or ""),
                        "last_coverage_alert_status": severity,
                        "last_coverage_alert_at": now.isoformat(),
                    }

                    await repo.upsert_state(
                        integration=integration,
                        scope="__coverage__",
                        metadata=metadata_update,
                    )

            if issues_handled or coverage_alerts:
                await db.commit()

        if issues_handled:
            logger.warning(
                "Integration sync health check surfaced %s issue(s)", issues_handled
            )
        if webhook_url and coverage_alerts:
            logger.warning(
                "Integration coverage alerts dispatched: %s", coverage_alerts
            )
        return {"issues": issues_handled, "coverage_alerts": coverage_alerts}

    return asyncio.run(_run())
