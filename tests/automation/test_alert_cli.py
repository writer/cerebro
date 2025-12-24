from __future__ import annotations

from datetime import UTC, datetime

from cerebro.automation.alerting import (
    AlertResult,
    AlertRule,
    RuleComparison,
    RuleSeverity,
)
from cerebro.automation.telemetry_health import TelemetryHealthSnapshot
from scripts import telemetry_alerts


def _snapshot() -> TelemetryHealthSnapshot:
    now = datetime.now(UTC)
    return TelemetryHealthSnapshot(
        generated_at=now,
        window_start=now,
        window_end=now,
        total_events=10,
        unique_orgs=1,
        unique_users=1,
        unique_sessions=1,
        events_by_type={},
        events_by_component={},
        missing_component=0,
        missing_metadata=0,
        empty_context=0,
        average_events_per_session=10.0,
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
        metric_value=10,
        triggered_at=now,
        message="Total events below threshold",
        severity=rule.severity,
        channels=rule.channels,
    )


def test_cli_prints_alerts(monkeypatch, capsys) -> None:
    async def fake_run(*args, **kwargs):
        return ((_alert(),), _snapshot())

    monkeypatch.setattr(telemetry_alerts, "run_telemetry_alerts", fake_run)

    exit_code = telemetry_alerts.main(["--dry-run", "--print-snapshot"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Triggered 1 telemetry alerts" in out
    assert '"generated_at"' in out


def test_cli_handles_no_alerts(monkeypatch, capsys) -> None:
    async def fake_run(*args, **kwargs):
        return ((), _snapshot())

    monkeypatch.setattr(telemetry_alerts, "run_telemetry_alerts", fake_run)

    exit_code = telemetry_alerts.main(["--dry-run"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "No telemetry alerts triggered" in out


def test_cli_exit_code_nonzero_on_fail_on_alerts(monkeypatch) -> None:
    async def fake_run(*args, **kwargs):
        return ((_alert(),), _snapshot())

    monkeypatch.setattr(telemetry_alerts, "run_telemetry_alerts", fake_run)

    exit_code = telemetry_alerts.main(["--dry-run", "--fail-on-alerts"])

    assert exit_code == 1


def test_cli_exit_code_threshold(monkeypatch) -> None:
    async def fake_run(*args, **kwargs):
        return ((_alert(),), _snapshot())

    monkeypatch.setattr(telemetry_alerts, "run_telemetry_alerts", fake_run)

    exit_code = telemetry_alerts.main(["--dry-run", "--fail-on-severity", "critical"])
    assert exit_code == 0

    exit_code = telemetry_alerts.main(["--dry-run", "--fail-on-severity", "warning"])
    assert exit_code == 1
