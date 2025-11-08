"""Celery task for evaluating operational health alerts."""

from __future__ import annotations

import asyncio
import logging
import smtplib
from email.mime.text import MIMEText
from typing import Any, Dict, List

import httpx

from cerebro.analytics.operations import collect_operational_alert_inputs
from cerebro.core.config import settings
from cerebro.core.database import async_session_factory

from .celery_app import celery_app

logger = logging.getLogger(__name__)


async def _send_slack_alert(title: str, message: str, severity: str, fields: Dict[str, Any]) -> None:
    webhook = settings.operational_alert_slack_webhook
    if not webhook:
        logger.debug("operational_slack_webhook_missing")
        return

    color = {
        "critical": "#dc2626",
        "error": "#dc2626",
        "warning": "#f97316",
        "info": "#2563eb",
    }.get(severity.lower(), "#2563eb")

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": title[:150]},
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": message[:2000],
                        },
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "\n".join(f"*{key}:* {value}" for key, value in fields.items()),
                            }
                        ],
                    },
                ],
            }
        ]
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(webhook, json=payload)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("operational_slack_alert_failed", error=str(exc))


async def _send_pagerduty_alert(title: str, message: str, severity: str, dedup_key: str) -> None:
    routing_key = settings.operational_alert_pagerduty_routing_key
    if not routing_key:
        logger.debug("operational_pagerduty_key_missing")
        return

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": title[:1024],
            "severity": severity if severity in {"info", "warning", "error", "critical"} else "warning",
            "source": "cerebro-operations",
            "component": "operational-health",
            "group": "cerebro",
            "class": "operational.alert",
            "custom_details": {
                "message": message,
            },
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post("https://events.pagerduty.com/v2/enqueue", json=payload)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("operational_pagerduty_alert_failed", error=str(exc))


async def _send_email_alert(subject: str, body: str) -> None:
    recipients = [email for email in settings.operational_alert_email_recipients if email]
    if not recipients:
        logger.debug("operational_email_recipients_missing")
        return

    sender = settings.operational_alert_email_sender
    if not sender:
        logger.debug("operational_email_sender_missing")
        return

    host = settings.operational_alert_smtp_host
    if not host:
        logger.debug("operational_email_smtp_missing")
        return

    port = settings.operational_alert_smtp_port
    username = settings.operational_alert_smtp_username
    password = settings.operational_alert_smtp_password

    message = MIMEText(body, "plain", "utf-8")
    message["Subject"] = subject[:200]
    message["From"] = sender
    message["To"] = ", ".join(recipients)

    def _send_sync() -> None:
        if settings.operational_alert_smtp_use_ssl:
            client = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            client = smtplib.SMTP(host, port, timeout=10)
        with client as smtp:
            if settings.operational_alert_smtp_use_tls and not settings.operational_alert_smtp_use_ssl:
                smtp.starttls()
            if username and password:
                smtp.login(username, password)
            smtp.sendmail(sender, recipients, message.as_string())

    try:
        await asyncio.to_thread(_send_sync)
    except Exception as exc:  # pragma: no cover - SMTP failures should not break task
        logger.warning("operational_email_alert_failed", error=str(exc))


async def _evaluate_alerts() -> Dict[str, Any]:
    async with async_session_factory() as db:
        metrics = await collect_operational_alert_inputs(db)

    alerts_sent: List[Dict[str, Any]] = []

    integration_threshold = max(1, settings.operational_integration_stale_hours) * 3600
    evidence_threshold = max(1, settings.operational_evidence_stale_hours) * 3600
    queue_threshold = max(1, settings.operational_celery_queue_threshold)
    db_threshold = max(0.0, min(1.0, settings.operational_db_pool_utilization_threshold))

    integrations = metrics.get("integrations", {}).get("items", [])
    stale_integrations = []
    evidence_lagging = []

    for item in integrations:
        age = item.get("age_seconds")
        status = item.get("status")
        integration_name = item.get("integration") or "unknown"
        scope = item.get("scope") or "default"

        if status == "error" or (age is not None and age >= integration_threshold):
            stale_integrations.append((integration_name, scope, age, status))

        metadata = item.get("metadata") or {}
        is_evidence = False
        for key in ("collector_type", "category", "workflow"):
            value = str(metadata.get(key, ""))
            if value and "evidence" in value.lower():
                is_evidence = True
                break
        if not is_evidence and "evidence" in integration_name.lower():
            is_evidence = True

        if is_evidence and (age is None or age >= evidence_threshold):
            evidence_lagging.append((integration_name, scope, age))

    if stale_integrations:
        names = ", ".join(f"{name} ({scope})" for name, scope, *_ in stale_integrations[:5])
        message = f"Detected {len(stale_integrations)} integrations with stale or failing syncs: {names}"
        await _send_slack_alert(
            title="Integration sync backlog",
            message=message,
            severity="warning" if len(stale_integrations) < 3 else "critical",
            fields={"threshold_hours": settings.operational_integration_stale_hours},
        )
        await _send_pagerduty_alert(
            title="Integration sync backlog",
            message=message,
            severity="error" if len(stale_integrations) >= 3 else "warning",
            dedup_key="operational-integrations-stale",
        )
        alerts_sent.append({"type": "integrations", "count": len(stale_integrations)})

    if evidence_lagging:
        lines = [
            f"- {name} ({scope}) last updated {('never' if age is None else f'{int(age // 3600)}h ago')}"
            for name, scope, age in evidence_lagging[:5]
        ]
        body = "Evidence collection appears to be behind schedule:\n" + "\n".join(lines)
        await _send_email_alert(
            subject="Cerebro evidence collection lagging",
            body=body,
        )
        alerts_sent.append({"type": "evidence", "count": len(evidence_lagging)})

    jobs_summary = metrics.get("jobs", {}).get("summary", {})
    queue_depth = jobs_summary.get("total_queue_depth", 0)
    if queue_depth >= queue_threshold:
        message = f"Celery queue depth is {queue_depth} tasks (threshold {queue_threshold})."
        await _send_slack_alert(
            title="Celery backlog detected",
            message=message,
            severity="critical",
            fields={"queue_depth": queue_depth},
        )
        await _send_pagerduty_alert(
            title="Celery backlog detected",
            message=message,
            severity="critical",
            dedup_key="operational-celery-backlog",
        )
        alerts_sent.append({"type": "celery", "queue_depth": queue_depth})

    pool_stats = metrics.get("database", {}).get("pool", {})
    utilization = pool_stats.get("utilization")
    if isinstance(utilization, (int, float)) and utilization >= db_threshold:
        message = f"Database pool utilization at {utilization:.2%} (threshold {db_threshold:.0%})."
        await _send_slack_alert(
            title="Database connection pool under pressure",
            message=message,
            severity="warning" if utilization < 0.95 else "critical",
            fields={"utilization": f"{utilization:.2%}"},
        )
        alerts_sent.append({"type": "database", "utilization": utilization})

    return {"alerts": alerts_sent}


@celery_app.task(name="cerebro.tasks.operational.evaluate_health")
def evaluate_operational_health() -> Dict[str, Any]:
    """Celery task entrypoint for operational health alert evaluation."""

    return asyncio.run(_evaluate_alerts())
