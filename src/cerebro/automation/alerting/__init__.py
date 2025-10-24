"""Alerting utilities for telemetry automation."""

from .config import default_rules, rules_from_env
from .rules import AlertRule, RuleComparison, RuleSeverity
from .results import AlertResult
from .evaluator import AlertCooldownStore, evaluate_rules
from .service import collect_telemetry_alerts

__all__ = [
    "AlertRule",
    "RuleComparison",
    "RuleSeverity",
    "AlertResult",
    "evaluate_rules",
    "default_rules",
    "rules_from_env",
    "AlertCooldownStore",
    "collect_telemetry_alerts",
]
