from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Sequence
from uuid import uuid4

import pytest

from cerebro.agents.tools.automation_summary import TelemetryAutomationSummaryTool
from cerebro.agents.tools.base import AgentContext
from cerebro.automation.alerting import AlertResult, AlertRule, RuleComparison, RuleSeverity
from cerebro.automation.telemetry_health import TelemetryHealthSnapshot


class _DummySession:
    async def __aenter__(self):  # type: ignore[override]
        return self

    async def __aexit__(self, exc_type, exc, tb):  # type: ignore[override]
        return False


def _snapshot() -> TelemetryHealthSnapshot:
    now = datetime.now(timezone.utc)
    return TelemetryHealthSnapshot(
        generated_at=now,
        window_start=now,
        window_end=now,
        total_events=200,
        unique_orgs=4,
        unique_users=20,
        unique_sessions=10,
        events_by_type={"load": 180},
        events_by_component={"dashboard": 140},
        missing_component=5,
        missing_metadata=30,
        empty_context=2,
        average_events_per_session=20.0,
        recent_events=[],
    )


def _alert(rule: AlertRule) -> AlertResult:
    return AlertResult(
        rule=rule,
        metric_value=15,
        triggered_at=datetime.now(timezone.utc),
        message=rule.format_message(15),
        severity=rule.severity,
        channels=rule.channels,
    )


@pytest.mark.asyncio
async def test_automation_tool_returns_summary(monkeypatch) -> None:
    from cerebro.agents.tools import automation_summary as module

    warning_rule = AlertRule(
        rule_id="low-events",
        metric="total_events",
        comparison=RuleComparison.LESS_THAN,
        threshold=50,
        severity=RuleSeverity.WARNING,
        description="Total events dropped below baseline",
    )

    async def fake_collect(*, rules: Optional[Sequence[AlertRule]] = None, **kwargs):
        return ((_alert(warning_rule),), _snapshot())

    monkeypatch.setattr(module, "default_rules", lambda: (warning_rule,))
    monkeypatch.setattr(module, "collect_telemetry_alerts", fake_collect)
    monkeypatch.setattr(module, "evaluate_health_thresholds", lambda snapshot, **_: ["missing metadata"])
    monkeypatch.setattr(module, "async_session_factory", lambda: _DummySession())

    tool = TelemetryAutomationSummaryTool()
    context = AgentContext(
        session_id=uuid4(),
        org_id=uuid4(),
        user_id="agent",
        agent_type="automation",
    )

    result = await tool._run(
        context=context,
        window_days=1,
        severity=None,
        max_missing_metadata_ratio=0.3,
        max_missing_component_ratio=0.1,
        min_total_events=10,
        limit_alerts=5,
    )

    assert result.success
    assert result.data is not None
    assert result.data["issues"] == ["missing metadata"]
    assert result.data["alerts"][0]["rule_id"] == "low-events"


@pytest.mark.asyncio
async def test_automation_tool_applies_severity_filter(monkeypatch) -> None:
    from cerebro.agents.tools import automation_summary as module

    info_rule = AlertRule(
        rule_id="info-signal",
        metric="noise",
        comparison=RuleComparison.GREATER_THAN,
        threshold=0.8,
        severity=RuleSeverity.INFO,
        description="Informational signal",
    )
    critical_rule = AlertRule(
        rule_id="critical-gap",
        metric="missing_metadata_ratio",
        comparison=RuleComparison.GREATER_THAN,
        threshold=0.5,
        severity=RuleSeverity.CRITICAL,
        description="Critical metadata gap",
    )

    captured_rules: list[Sequence[AlertRule]] = []

    async def fake_collect(*, rules: Optional[Sequence[AlertRule]] = None, **kwargs):
        captured_rules.append(tuple(rules or ()))
        return (tuple(), _snapshot())

    monkeypatch.setattr(module, "default_rules", lambda: (info_rule, critical_rule))
    monkeypatch.setattr(module, "collect_telemetry_alerts", fake_collect)
    monkeypatch.setattr(module, "evaluate_health_thresholds", lambda snapshot, **_: [])
    monkeypatch.setattr(module, "async_session_factory", lambda: _DummySession())

    tool = TelemetryAutomationSummaryTool()
    context = AgentContext(
        session_id=uuid4(),
        org_id=uuid4(),
        user_id="agent",
        agent_type="automation",
    )

    await tool._run(
        context=context,
        window_days=1,
        severity=RuleSeverity.CRITICAL,
        max_missing_metadata_ratio=0.3,
        max_missing_component_ratio=0.1,
        min_total_events=10,
        limit_alerts=5,
    )

    assert captured_rules
    assert all(rule.severity == RuleSeverity.CRITICAL for rule in captured_rules[0])


@pytest.mark.asyncio
async def test_automation_tool_respects_limit(monkeypatch) -> None:
    from cerebro.agents.tools import automation_summary as module

    rules = [
        AlertRule(
            rule_id=f"rule-{idx}",
            metric="metric",
            comparison=RuleComparison.GREATER_THAN,
            threshold=1,
            severity=RuleSeverity.WARNING,
            description="Test rule",
        )
        for idx in range(3)
    ]

    async def fake_collect(*, rules: Optional[Sequence[AlertRule]] = None, **kwargs):
        alerts = tuple(_alert(rule) for rule in rules or tuple())
        return (alerts, _snapshot())

    monkeypatch.setattr(module, "default_rules", lambda: tuple(rules))
    monkeypatch.setattr(module, "collect_telemetry_alerts", fake_collect)
    monkeypatch.setattr(module, "evaluate_health_thresholds", lambda snapshot, **_: [])
    monkeypatch.setattr(module, "async_session_factory", lambda: _DummySession())

    tool = TelemetryAutomationSummaryTool()
    context = AgentContext(
        session_id=uuid4(),
        org_id=uuid4(),
        user_id="agent",
        agent_type="automation",
    )

    result = await tool._run(
        context=context,
        window_days=1,
        severity=None,
        max_missing_metadata_ratio=0.3,
        max_missing_component_ratio=0.1,
        min_total_events=10,
        limit_alerts=1,
    )

    assert result.success
    assert len(result.data["alerts"]) == 1
