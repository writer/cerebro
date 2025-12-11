from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Sequence


from cerebro.automation.alerting import AlertResult, AlertRule, RuleComparison, RuleSeverity
from cerebro.automation.telemetry_health import TelemetryHealthSnapshot


def _snapshot() -> TelemetryHealthSnapshot:
    now = datetime.now(timezone.utc)
    return TelemetryHealthSnapshot(
        generated_at=now,
        window_start=now,
        window_end=now,
        total_events=100,
        unique_orgs=5,
        unique_users=12,
        unique_sessions=8,
        events_by_type={"load": 80},
        events_by_component={"dashboard": 60},
        missing_component=3,
        missing_metadata=12,
        empty_context=1,
        average_events_per_session=12.5,
        recent_events=[],
    )


def _alert(rule_id: str = "low-events") -> AlertResult:
    rule = AlertRule(
        rule_id=rule_id,
        metric="total_events",
        comparison=RuleComparison.LESS_THAN,
        threshold=50,
        severity=RuleSeverity.WARNING,
        description="Total events below expected baseline",
    )
    trigger_time = datetime.now(timezone.utc)
    return AlertResult(
        rule=rule,
        metric_value=20,
        triggered_at=trigger_time,
        message=rule.format_message(20),
        severity=rule.severity,
        channels=rule.channels,
    )


def test_health_requires_auth(client) -> None:
    response = client.get("/api/v1/automation/telemetry/health")
    assert response.status_code in {401, 403}


def test_health_returns_snapshot(monkeypatch, client, admin_token) -> None:
    from cerebro.api.routers import automation

    async def fake_fetch(*args, **kwargs):
        return _snapshot()

    def fake_evaluate(snapshot, **kwargs):
        return ["missing metadata ratio high"]

    monkeypatch.setattr(automation, "fetch_telemetry_health", fake_fetch)
    monkeypatch.setattr(automation, "evaluate_health_thresholds", fake_evaluate)

    response = client.get(
        "/api/v1/automation/telemetry/health",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["issues"] == ["missing metadata ratio high"]
    assert payload["snapshot"]["total_events"] == 100


def test_alerts_preview_returns_alerts(monkeypatch, client, admin_token) -> None:
    from cerebro.api.routers import automation

    async def fake_collect(*, rules: Optional[Sequence[AlertRule]] = None, **kwargs):
        return ((_alert(),), _snapshot())

    monkeypatch.setattr(automation, "collect_telemetry_alerts", fake_collect)

    response = client.get(
        "/api/v1/automation/telemetry/alerts",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["alerts"][0]["rule_id"] == "low-events"
    assert payload["snapshot"]["total_events"] == 100


def test_alerts_preview_filters_rules(monkeypatch, client, admin_token) -> None:
    from cerebro.api.routers import automation

    captured: List[Sequence[AlertRule]] = []

    async def fake_collect(*, rules: Optional[Sequence[AlertRule]] = None, **kwargs):
        captured.append(tuple(rules or ()))
        return (tuple(), _snapshot())

    monkeypatch.setattr(automation, "collect_telemetry_alerts", fake_collect)

    response = client.get(
        "/api/v1/automation/telemetry/alerts?rule_id=low-events",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    assert captured
    assert all(rule.rule_id == "low-events" for rule in captured[0])


def test_alerts_preview_unknown_rule_returns_empty(monkeypatch, client, admin_token) -> None:
    from cerebro.api.routers import automation

    async def fake_collect(*args, **kwargs):
        return (tuple(), _snapshot())

    monkeypatch.setattr(automation, "collect_telemetry_alerts", fake_collect)

    response = client.get(
        "/api/v1/automation/telemetry/alerts?rule_id=does-not-exist",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["alerts"] == []


def test_health_validates_window_days(client, admin_token) -> None:
    response = client.get(
        "/api/v1/automation/telemetry/health",
        params={"window_days": 0},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 422
