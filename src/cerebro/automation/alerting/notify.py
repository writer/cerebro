"""Notification delivery helpers for telemetry alerts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Awaitable, Callable, Iterable, Mapping, Optional, Sequence

import httpx

from ..telemetry_health import TelemetryHealthSnapshot
from .results import AlertResult


@dataclass
class NotificationContext:
    snapshot: TelemetryHealthSnapshot
    alerts: Sequence[AlertResult]


async def send_slack_alert(
    webhook_url: str,
    alert: AlertResult,
    *,
    session: Optional[httpx.AsyncClient] = None,
    timeout: float = 10.0,
) -> None:
    payload = {
        "text": alert.message,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{alert.rule.description}*\n{alert.message}",
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Severity: *{alert.severity.value}*  •  Rule: `{alert.rule.rule_id}`",
                    }
                ],
            },
        ],
    }

    close_session = False
    client = session
    if client is None:
        client = httpx.AsyncClient(timeout=timeout)
        close_session = True

    try:
        response = await client.post(webhook_url, json=payload)
        response.raise_for_status()
    finally:
        if close_session:
            await client.aclose()


def _email_subject(alert: AlertResult) -> str:
    return f"[Cerebro] {alert.severity.value.upper()} telemetry alert"


def _email_body(alert: AlertResult, snapshot: TelemetryHealthSnapshot) -> str:
    lines = [
        f"Alert: {alert.rule.description}",
        f"Message: {alert.message}",
        f"Metric: {alert.rule.metric}",
        f"Threshold: {alert.rule.threshold}",
        f"Value: {alert.metric_value}",
        f"Triggered at: {alert.triggered_at.isoformat()}",
        "",
        "Snapshot totals:",
        f"  Total events: {snapshot.total_events}",
        f"  Missing metadata: {snapshot.missing_metadata} ({snapshot.missing_metadata_ratio():.2%})",
        f"  Missing component: {snapshot.missing_component} ({snapshot.missing_component_ratio():.2%})",
    ]
    return "\n".join(lines)


async def send_email_alert(
    send_email: Callable[[Sequence[str], str, str], Awaitable[None]],
    recipients: Sequence[str],
    alert: AlertResult,
    snapshot: TelemetryHealthSnapshot,
) -> None:
    if not recipients:
        return
    subject = _email_subject(alert)
    body = _email_body(alert, snapshot)
    await send_email(recipients, subject, body)
