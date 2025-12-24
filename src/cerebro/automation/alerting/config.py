"""Helpers for retrieving alert rules from defaults or environment overrides."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping, Sequence

from .rules import AlertRule, load_rules

_DEFAULT_RULE_DEFINITIONS: Sequence[dict[str, object]] = (
    {
        "rule_id": "telemetry-total-events-low",
        "metric": "total_events",
        "comparison": "lt",
        "threshold": 100.0,
        "severity": "critical",
        "description": "Telemetry events dropped below acceptable threshold",
        "channels": ["slack"],
        "cooldown_minutes": 120,
    },
    {
        "rule_id": "telemetry-missing-metadata",
        "metric": "missing_metadata_ratio",
        "comparison": "gt",
        "threshold": 0.25,
        "severity": "warning",
        "description": "Missing telemetry metadata is elevated",
        "channels": ["slack"],
        "cooldown_minutes": 60,
    },
    {
        "rule_id": "telemetry-missing-component",
        "metric": "missing_component_ratio",
        "comparison": "gt",
        "threshold": 0.1,
        "severity": "warning",
        "description": "Missing component identifiers detected",
        "channels": ["slack"],
        "cooldown_minutes": 60,
    },
)


def default_rules() -> tuple[AlertRule, ...]:
    """Return the built-in rule set."""

    return load_rules(_DEFAULT_RULE_DEFINITIONS)


def rules_from_env(
    env: Mapping[str, str] | None = None,
    *,
    env_var: str = "CEREBRO_TELEMETRY_ALERT_RULES",
) -> tuple[AlertRule, ...]:
    """Load rules from an environment variable containing JSON definitions."""

    mapping = env or os.environ
    raw = mapping.get(env_var)
    if not raw:
        return default_rules()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise ValueError(f"Invalid JSON in {env_var}") from exc

    if not isinstance(parsed, Iterable):  # pragma: no cover - defensive
        raise ValueError(f"Rule override must be iterable, got {type(parsed)!r}")

    return load_rules(parsed)
