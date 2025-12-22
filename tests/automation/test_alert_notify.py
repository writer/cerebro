from __future__ import annotations

from datetime import datetime, timezone
from typing import List

import httpx
import pytest

from cerebro.automation.alerting import (
    AlertResult,
    AlertRule,
    RuleComparison,
    RuleSeverity,
)
from cerebro.automation.alerting.notify import send_email_alert, send_slack_alert
from cerebro.automation.telemetry_health import TelemetryHealthSnapshot


def _rule() -> AlertRule:
    return AlertRule(
        rule_id="test",
        metric="missing_metadata_ratio",
        comparison=RuleComparison.GREATER_THAN,
        threshold=0.25,
        severity=RuleSeverity.CRITICAL,
        description="Missing metadata too high",
    )


def _snapshot() -> TelemetryHealthSnapshot:
    now = datetime.now(timezone.utc)
    return TelemetryHealthSnapshot(
        generated_at=now,
        window_start=now,
        window_end=now,
        total_events=100,
        unique_orgs=5,
        unique_users=10,
        unique_sessions=8,
        events_by_type={},
        events_by_component={},
        missing_component=2,
        missing_metadata=40,
        empty_context=3,
        average_events_per_session=12.5,
        recent_events=[],
    )


def _result(rule: AlertRule) -> AlertResult:
    now = datetime.now(timezone.utc)
    return AlertResult(
        rule=rule,
        metric_value=0.4,
        triggered_at=now,
        message="Missing metadata ratio 0.40 exceeds limit 0.25",
        severity=rule.severity,
        channels=rule.channels,
    )


@pytest.mark.asyncio
async def test_send_slack_alert_posts_payload(monkeypatch) -> None:
    calls: List[dict[str, object]] = []

    async def fake_post(url, json):  # type: ignore[override]
        calls.append({"url": url, "json": json})
        return httpx.Response(200, request=httpx.Request("POST", url))

    async with httpx.AsyncClient() as client:
        monkeypatch.setattr(client, "post", fake_post)  # type: ignore[arg-type]

        await send_slack_alert(
            "https://slack.example", _result(_rule()), session=client
        )

    assert calls
    payload = calls[0]["json"]
    assert payload["text"]


@pytest.mark.asyncio
async def test_send_email_alert_calls_sender(monkeypatch) -> None:
    captured: List[tuple] = []

    async def fake_send(recipients, subject, body):
        captured.append((tuple(recipients), subject, body))

    await send_email_alert(
        fake_send, ["test@example.com"], _result(_rule()), _snapshot()
    )

    assert captured
    recipients, subject, body = captured[0]
    assert "test@example.com" in recipients
    assert "CRITICAL" in subject
    assert "Missing metadata" in body
