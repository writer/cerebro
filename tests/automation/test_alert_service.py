from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cerebro.automation.alerting import (
    AlertResult,
    AlertRule,
    RuleComparison,
    RuleSeverity,
    collect_telemetry_alerts,
)
from cerebro.automation.alerting.evaluator import AlertCooldownStore
from cerebro.automation.telemetry_health import TelemetryHealthSnapshot


class _DummyStore(AlertCooldownStore):
    async def should_suppress(self, rule: AlertRule, *, now: datetime) -> bool:
        return False

    async def record_fire(self, result: AlertResult) -> None:
        return None


@pytest.mark.asyncio
async def test_collect_telemetry_alerts_uses_rules(monkeypatch) -> None:
    now = datetime.now(timezone.utc)
    snapshot = TelemetryHealthSnapshot(
        generated_at=now,
        window_start=now,
        window_end=now,
        total_events=10,
        unique_orgs=1,
        unique_users=1,
        unique_sessions=1,
        events_by_type={"view": 10},
        events_by_component={"dashboard": 10},
        missing_component=0,
        missing_metadata=0,
        empty_context=0,
        average_events_per_session=10.0,
        recent_events=[],
    )

    async def fake_fetch(window_days: int, *, db_session=None):  # type: ignore[override]
        assert window_days == 7
        return snapshot

    monkeypatch.setattr(
        "cerebro.automation.alerting.service.fetch_telemetry_health",
        fake_fetch,
    )

    rule = AlertRule(
        rule_id="low-total",
        metric="total_events",
        comparison=RuleComparison.LESS_THAN,
        threshold=20,
        severity=RuleSeverity.WARNING,
        description="Low event count",
    )

    alerts, returned_snapshot = await collect_telemetry_alerts(
        rules=[rule],
        cooldown_store=_DummyStore(),
    )

    assert returned_snapshot is snapshot
    assert len(alerts) == 1
    assert alerts[0].rule.rule_id == "low-total"
