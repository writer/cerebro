"""High-level orchestration for telemetry alerting."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Awaitable, Callable, Iterable, Optional, Sequence

import httpx
import redis.asyncio as redis

from cerebro.core.database import async_session_factory

from ..telemetry_health import TelemetryHealthSnapshot
from .evaluator import AlertCooldownStore
from .notify import send_email_alert, send_slack_alert
from .results import AlertResult
from .service import collect_telemetry_alerts
from .store import InMemoryCooldownStore, RedisCooldownStore
from .rules import AlertRule

logger = logging.getLogger(__name__)


EmailSender = Callable[[Sequence[str], str, str], Awaitable[None]]


@asynccontextmanager
async def _build_redis_store(redis_url: Optional[str]) -> AlertCooldownStore | None:
    if not redis_url:
        yield None
        return

    client = redis.from_url(redis_url)
    try:
        yield RedisCooldownStore(client)
    finally:
        await client.aclose()


async def run_telemetry_alerts(
    *,
    window_days: int = 7,
    slack_webhooks: Sequence[str] | None = None,
    email_recipients: Sequence[str] | None = None,
    redis_url: Optional[str] = None,
    dry_run: bool = False,
    rules: Optional[Sequence[AlertRule]] = None,
    email_sender: Optional[EmailSender] = None,
    http_client: Optional[httpx.AsyncClient] = None,
) -> tuple[tuple[AlertResult, ...], TelemetryHealthSnapshot]:
    slack_webhooks = tuple(slack_webhooks or ())
    email_recipients = tuple(email_recipients or ())

    client_provided = http_client is not None
    if http_client is None:
        http_client = httpx.AsyncClient(timeout=10.0)

    if email_sender is None:
        async def email_sender(recipients: Sequence[str], subject: str, body: str) -> None:
            logger.info(
                "telemetry_alert_email recipients=%s subject=%s preview=%s",
                list(recipients),
                subject,
                body[:256],
            )

    async with _build_redis_store(redis_url) as redis_store:
        store: AlertCooldownStore | None = redis_store if redis_store else None

        if store is None and (slack_webhooks or email_recipients):
            store = InMemoryCooldownStore()

        async with async_session_factory() as session:
            alerts, snapshot = await collect_telemetry_alerts(
                window_days=window_days,
                rules=rules,
                cooldown_store=store,
                db_session=session,
            )

    if dry_run:
        for alert in alerts:
            logger.info(
                "telemetry_alert_dry_run rule=%s severity=%s message=%s",
                alert.rule.rule_id,
                alert.severity.value,
                alert.message,
            )
    else:
        for alert in alerts:
            for webhook in slack_webhooks:
                try:
                    await send_slack_alert(webhook, alert, session=http_client)
                except Exception:  # pragma: no cover - defensive logging
                    logger.exception("telemetry_alert_slack_failed webhook=%s", webhook)

            if email_recipients:
                try:
                    await send_email_alert(email_sender, email_recipients, alert, snapshot)
                except Exception:  # pragma: no cover - defensive logging
                    logger.exception(
                        "telemetry_alert_email_failed recipients=%s",
                        list(email_recipients),
                    )

    if not client_provided:
        await http_client.aclose()

    if alerts:
        logger.info(
            "telemetry_alerts_emitted count=%s rules=%s",
            len(alerts),
            [alert.rule.rule_id for alert in alerts],
        )
    else:
        logger.info("telemetry_alerts_none")

    return alerts, snapshot
