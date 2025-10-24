from __future__ import annotations

import json

from cerebro.automation.alerting import AlertRule, default_rules, rules_from_env


def test_default_rules_available() -> None:
    rules = default_rules()
    assert isinstance(rules, tuple)
    assert rules
    assert all(isinstance(rule, AlertRule) for rule in rules)


def test_env_override_allows_custom_rules(monkeypatch) -> None:
    payload = [
        {
            "rule_id": "custom",
            "metric": "total_events",
            "comparison": "gt",
            "threshold": 500.0,
            "severity": "info",
            "description": "High throughput",
            "channels": ["slack"],
        }
    ]
    monkeypatch.setenv("CEREBRO_TELEMETRY_ALERT_RULES", json.dumps(payload))

    rules = rules_from_env()
    assert len(rules) == 1
    rule = rules[0]
    assert rule.rule_id == "custom"
    assert rule.threshold == 500.0
