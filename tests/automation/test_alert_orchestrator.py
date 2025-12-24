from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cerebro.automation.alerting import (
    AlertResult,
    AlertRule,
    RuleComparison,
    RuleSeverity,
    run_telemetry_alerts,
)
from cerebro.automation.telemetry_health import TelemetryHealthSnapshot


class _DummySession:
    async def __aenter__(self):  # type: ignore[override]
        return self

    async def __aexit__(self, exc_type, exc, tb):  # type: ignore[override]
        return False


def _snapshot() -> TelemetryHealthSnapshot:
    now = datetime.now(UTC)
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
        missing_component=0,
        missing_metadata=0,
        empty_context=0,
        average_events_per_session=12.5,
        recent_events=[],
    )


def _alert() -> AlertResult:
    rule = AlertRule(
        rule_id="low-events",
        metric="total_events",
        comparison=RuleComparison.LESS_THAN,
        threshold=50,
        severity=RuleSeverity.WARNING,
        description="Total events below threshold",
    )
    now = datetime.now(UTC)
    return AlertResult(
        rule=rule,
        metric_value=20,
        triggered_at=now,
        message="Total events below threshold",
        severity=rule.severity,
        channels=rule.channels,
    )


@pytest.mark.asyncio
async def test_run_telemetry_alerts_no_alerts(monkeypatch) -> None:
    from cerebro.automation.alerting import orchestrator

    monkeypatch.setattr(orchestrator, "async_session_factory", lambda: _DummySession())

    async def fake_collect(**kwargs):
        return (), _snapshot()

    monkeypatch.setattr(orchestrator, "collect_telemetry_alerts", fake_collect)

    alerts, snapshot = await run_telemetry_alerts(dry_run=True)

    assert not alerts
    assert isinstance(snapshot, TelemetryHealthSnapshot)


@pytest.mark.asyncio
async def test_run_telemetry_alerts_delivers_notifications(monkeypatch) -> None:
    from cerebro.automation.alerting import orchestrator

    monkeypatch.setattr(orchestrator, "async_session_factory", lambda: _DummySession())

    async def fake_collect(**kwargs):
        return (_alert(),), _snapshot()

    monkeypatch.setattr(orchestrator, "collect_telemetry_alerts", fake_collect)

    slack_calls: list[str] = []

    async def fake_slack(webhook, alert, session=None):
        slack_calls.append(webhook)

    monkeypatch.setattr(orchestrator, "send_slack_alert", fake_slack)

    email_calls: list[str] = []

    async def fake_email(recipients, subject, body):
        email_calls.extend(recipients)

    alerts, snapshot = await run_telemetry_alerts(
        slack_webhooks=["https://slack.example"],
        email_recipients=["ops@example.com"],
        email_sender=fake_email,
    )

    assert len(alerts) == 1
    assert slack_calls == ["https://slack.example"]
    assert email_calls == ["ops@example.com"]
