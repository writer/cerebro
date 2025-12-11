from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cerebro.automation.alerting import (
    AlertResult,
    AlertRule,
    InMemoryCooldownStore,
    RuleComparison,
    RuleSeverity,
    collect_telemetry_alerts,
    run_telemetry_alerts,
)
from cerebro.automation.telemetry_health import TelemetryHealthSnapshot


class _FakeSession:
    async def __aenter__(self):  # type: ignore[override]
        return self

    async def __aexit__(self, exc_type, exc, tb):  # type: ignore[override]
        return False


def _snapshot(missing_metadata: int = 50, total_events: int = 100) -> TelemetryHealthSnapshot:
    now = datetime.now(timezone.utc)
    return TelemetryHealthSnapshot(
        generated_at=now,
        window_start=now,
        window_end=now,
        total_events=total_events,
        unique_orgs=5,
        unique_users=10,
        unique_sessions=8,
        events_by_type={},
        events_by_component={},
        missing_component=0,
        missing_metadata=missing_metadata,
        empty_context=0,
        average_events_per_session=12.5,
        recent_events=[],
    )


@pytest.mark.asyncio
async def test_collect_and_evaluate_rules_end_to_end(monkeypatch) -> None:
    from cerebro.automation.alerting import service

    async def fake_fetch(window_days: int, *, db_session=None):  # type: ignore[override]
        return _snapshot()

    monkeypatch.setattr(service, "fetch_telemetry_health", fake_fetch)

    rule = AlertRule(
        rule_id="missing-metadata",
        metric="missing_metadata_ratio",
        comparison=RuleComparison.GREATER_THAN,
        threshold=0.2,
        severity=RuleSeverity.WARNING,
        description="Missing metadata ratio high",
    )

    store = InMemoryCooldownStore()
    alerts, snapshot = await collect_telemetry_alerts(
        rules=[rule],
        cooldown_store=store,
    )

    assert len(alerts) == 1
    assert snapshot.missing_metadata_ratio() == pytest.approx(0.5)

    # ensure cooldown suppresses subsequent evaluation
    alerts_second, _ = await collect_telemetry_alerts(rules=[rule], cooldown_store=store)
    assert not alerts_second


@pytest.mark.asyncio
async def test_run_orchestrator_handles_delivery_errors(monkeypatch) -> None:
    from cerebro.automation.alerting import orchestrator

    async def fake_collect(**kwargs):
        rule = AlertRule(
            rule_id="low-events",
            metric="total_events",
            comparison=RuleComparison.LESS_THAN,
            threshold=50,
            severity=RuleSeverity.WARNING,
            description="Low total events",
        )
        now = datetime.now(timezone.utc)
        alert = AlertResult(
            rule=rule,
            metric_value=20,
            triggered_at=now,
            message="Low total events",
            severity=rule.severity,
            channels=rule.channels,
        )
        return (alert,), _snapshot(total_events=20)

    monkeypatch.setattr(orchestrator, "async_session_factory", lambda: _FakeSession())
    monkeypatch.setattr(orchestrator, "collect_telemetry_alerts", fake_collect)

    async def failing_slack(*args, **kwargs):
        raise RuntimeError("Slack failure")

    async def failing_email(*args, **kwargs):
        raise RuntimeError("Email failure")

    monkeypatch.setattr(orchestrator, "send_slack_alert", failing_slack)

    alerts, snapshot = await run_telemetry_alerts(
        slack_webhooks=["https://example"],
        email_recipients=["ops@example.com"],
        email_sender=failing_email,
    )

    assert len(alerts) == 1
    assert snapshot.total_events == 20
