"""Periodic monitoring for agent runtime health."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any

import httpx

from cerebro.analytics.runtime_health import summarize_runtime_health
from cerebro.core.config import settings
from cerebro.core.database import async_session_factory

from .celery_app import celery_app

logger = logging.getLogger(__name__)


async def _post_slack_message(webhook_url: str, payload: Dict[str, Any]) -> None:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(webhook_url, json=payload)
        response.raise_for_status()


def _build_runtime_alert_payload(
    runtime: str, severity: str, warning_count: int, error_count: int, window_hours: int
) -> Dict[str, Any]:
    title = f"{runtime.title()} runtime health {severity.upper()}"
    now = datetime.now(timezone.utc)
    text = (
        f"Detected {warning_count} warning(s) and {error_count} error(s) "
        f"for the {runtime} runtime in the last {window_hours}h."
    )

    color = {
        "critical": "#d32f2f",
        "warning": "#f57c00",
    }.get(severity, "#1976d2")

    return {
        "text": text,
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": title},
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Warnings:* {warning_count}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Errors:* {error_count}",
                            },
                        ],
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": (
                                    f"<!date^{int(now.timestamp())}^{{date_short_pretty}} at {{time}}|"
                                    f"{now.isoformat()}> • Window: last {window_hours}h"
                                ),
                            }
                        ],
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "Review /api/v1/analytics/runtime-health for detailed breakdown.",
                            }
                        ],
                    },
                ],
            }
        ],
    }


@celery_app.task(bind=True, name="cerebro.tasks.runtime.monitor_health")
def monitor_runtime_health(self):
    async def _run() -> Dict[str, Any]:
        if not settings or not settings.runtime_health_alert_webhook:
            logger.debug("runtime_health_alerts_disabled")
            return {"alerts": 0}

        window_hours = max(1, getattr(settings, "runtime_health_alert_window_hours", 1))
        warning_threshold = max(
            1, getattr(settings, "runtime_health_warning_threshold", 3)
        )
        error_threshold = max(1, getattr(settings, "runtime_health_error_threshold", 1))

        async with async_session_factory() as db:
            summaries = await summarize_runtime_health(db, hours=window_hours)

        alerts_sent = 0
        for summary in summaries:
            runtime = summary.get("runtime", "unknown")
            events = summary.get("events", {})
            warning_count = events.get("runtime_warning", {}).get("count", 0)
            error_count = events.get("runtime_error", {}).get("count", 0)

            severity: str | None = None
            if error_count >= error_threshold:
                severity = "critical"
            elif warning_count >= warning_threshold:
                severity = "warning"

            if not severity:
                continue

            payload = _build_runtime_alert_payload(
                runtime=runtime,
                severity=severity,
                warning_count=warning_count,
                error_count=error_count,
                window_hours=window_hours,
            )

            try:
                await _post_slack_message(
                    settings.runtime_health_alert_webhook, payload
                )
                alerts_sent += 1
            except httpx.HTTPError:
                logger.exception(
                    "runtime_health_alert_failed", runtime=runtime, severity=severity
                )

        return {"alerts": alerts_sent}

    return asyncio.run(_run())
