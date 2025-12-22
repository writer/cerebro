from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cerebro.automation.alerting import (
    AlertResult,
    AlertRule,
    RuleComparison,
    RuleSeverity,
    evaluate_rules,
)
from cerebro.automation.alerting.evaluator import AlertCooldownStore
from cerebro.automation.telemetry_health import TelemetryHealthSnapshot


def _make_snapshot(
    *,
    total_events: int = 100,
    missing_metadata: int = 25,
    missing_component: int = 5,
    events_by_type: dict[str, int] | None = None,
    events_by_component: dict[str, int] | None = None,
) -> TelemetryHealthSnapshot:
    now = datetime.now(timezone.utc)
    return TelemetryHealthSnapshot(
        generated_at=now,
        window_start=now,
        window_end=now,
        total_events=total_events,
        unique_orgs=10,
        unique_users=20,
        unique_sessions=15,
        events_by_type=events_by_type or {"click": 60, "view": 40},
        events_by_component=events_by_component or {"dashboard": 50, "settings": 10},
        missing_component=missing_component,
        missing_metadata=missing_metadata,
        empty_context=3,
        average_events_per_session=total_events / 15,
        recent_events=[],
    )


@pytest.mark.asyncio
async def test_rule_triggers_on_threshold_breach() -> None:
    snapshot = _make_snapshot(missing_metadata=40)
    rule = AlertRule(
        rule_id="missing-metadata",
        metric="missing_metadata_ratio",
        comparison=RuleComparison.GREATER_THAN,
        threshold=0.2,
        severity=RuleSeverity.WARNING,
        description="Missing metadata ratio too high",
    )

    results = await evaluate_rules(snapshot, [rule])

    assert len(results) == 1
    result = results[0]
    assert result.rule is rule
    assert result.metric_value == pytest.approx(snapshot.missing_metadata_ratio())
    assert "Missing metadata" in result.message


@pytest.mark.asyncio
async def test_rule_ignores_when_condition_not_met() -> None:
    snapshot = _make_snapshot(missing_metadata=5)
    rule = AlertRule(
        rule_id="missing-metadata",
        metric="missing_metadata_ratio",
        comparison=RuleComparison.GREATER_THAN,
        threshold=0.5,
        severity=RuleSeverity.WARNING,
        description="Missing metadata ratio too high",
    )

    results = await evaluate_rules(snapshot, [rule])
    assert not results


@pytest.mark.asyncio
async def test_rule_supports_event_type_metric() -> None:
    snapshot = _make_snapshot(events_by_type={"error": 7})
    rule = AlertRule(
        rule_id="error-events",
        metric="events_by_type.error",
        comparison=RuleComparison.GREATER_THAN_OR_EQUAL,
        threshold=5,
        severity=RuleSeverity.INFO,
        description="Error event volume high",
        message_template="{description}: value={value} threshold={threshold}",
    )

    results = await evaluate_rules(snapshot, [rule])
    assert len(results) == 1
    assert "value=" in results[0].message


class _MemoryCooldownStore(AlertCooldownStore):
    def __init__(self) -> None:
        self._suppressed = False
        self.last_recorded_rule: str | None = None

    async def should_suppress(
        self, rule: AlertRule, *, now: datetime
    ) -> bool:  # noqa: D401
        return self._suppressed

    async def record_fire(self, result: AlertResult) -> None:
        self.last_recorded_rule = result.rule.rule_id
        self._suppressed = True


@pytest.mark.asyncio
async def test_rule_respects_cooldown_store() -> None:
    snapshot = _make_snapshot(missing_metadata=40)
    rule = AlertRule(
        rule_id="missing-metadata",
        metric="missing_metadata_ratio",
        comparison=RuleComparison.GREATER_THAN,
        threshold=0.1,
        severity=RuleSeverity.CRITICAL,
        description="Missing metadata ratio too high",
        cooldown_minutes=30,
    )

    store = _MemoryCooldownStore()

    first = await evaluate_rules(snapshot, [rule], cooldown_store=store)
    assert len(first) == 1
    assert store.last_recorded_rule == "missing-metadata"

    second = await evaluate_rules(snapshot, [rule], cooldown_store=store)
    assert not second
