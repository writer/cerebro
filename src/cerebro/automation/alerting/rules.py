"""Rule definitions for telemetry alerting."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RuleSeverity(str, Enum):
    """Severity levels applied to fired alerts."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class RuleComparison(str, Enum):
    """Supported comparison operators for alert thresholds."""

    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUAL = "lte"


DEFAULT_CHANNELS: tuple[str, ...] = ("slack",)


@dataclass
class AlertRule:
    """Configuration describing when an alert should fire."""

    rule_id: str
    metric: str
    comparison: RuleComparison
    threshold: float
    severity: RuleSeverity
    description: str
    channels: tuple[str, ...] = DEFAULT_CHANNELS
    cooldown_minutes: int = 60
    message_template: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def format_message(self, metric_value: float) -> str:
        """Render a human-readable message for the fired alert."""

        if self.message_template:
            return self.message_template.format(
                metric=self.metric,
                value=f"{metric_value:.4f}",
                threshold=f"{self.threshold:.4f}",
                description=self.description,
            )
        return (
            f"{self.description} — metric '{self.metric}' value={metric_value:.4f} "
            f"breached threshold {self.comparison.value} {self.threshold:.4f}"
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> AlertRule:
        """Construct a rule from a dictionary definition."""

        try:
            rule_id = str(payload["rule_id"])
            metric = str(payload["metric"])
            comparison = RuleComparison(payload["comparison"])
            threshold = float(payload["threshold"])
            severity = RuleSeverity(payload.get("severity", RuleSeverity.WARNING))
            description = str(payload.get("description", metric))
        except (KeyError, ValueError, TypeError) as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid rule configuration: {payload}") from exc

        channels: Sequence[str] = payload.get("channels", DEFAULT_CHANNELS)
        cooldown_minutes = int(payload.get("cooldown_minutes", 60))
        message_template = payload.get("message_template")
        metadata = payload.get("metadata", {})

        return cls(
            rule_id=rule_id,
            metric=metric,
            comparison=comparison,
            threshold=threshold,
            severity=severity,
            description=description,
            channels=tuple(channels) or DEFAULT_CHANNELS,
            cooldown_minutes=cooldown_minutes,
            message_template=message_template,
            metadata=metadata,
        )


def load_rules(definitions: Iterable[Mapping[str, Any]]) -> tuple[AlertRule, ...]:
    """Parse a collection of dictionary definitions into alert rules."""

    rules = [AlertRule.from_dict(item) for item in definitions]
    return tuple(rules)
