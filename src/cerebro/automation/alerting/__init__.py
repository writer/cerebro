"""Alerting utilities for telemetry automation."""

from .config import default_rules, rules_from_env
from .evaluator import AlertCooldownStore, evaluate_rules
from .orchestrator import run_telemetry_alerts
from .results import AlertResult
from .rules import AlertRule, RuleComparison, RuleSeverity
from .service import collect_telemetry_alerts
from .store import InMemoryCooldownStore, RedisCooldownStore

__all__ = [
    "AlertCooldownStore",
    "AlertResult",
    "AlertRule",
    "InMemoryCooldownStore",
    "RedisCooldownStore",
    "RuleComparison",
    "RuleSeverity",
    "collect_telemetry_alerts",
    "default_rules",
    "evaluate_rules",
    "rules_from_env",
    "run_telemetry_alerts",
]
