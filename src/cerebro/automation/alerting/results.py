"""Alert evaluation results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Tuple

from .rules import AlertRule, RuleSeverity


@dataclass(slots=True)
class AlertResult:
    """Represents a fired alert after rule evaluation."""

    rule: AlertRule
    metric_value: float
    triggered_at: datetime
    message: str
    severity: RuleSeverity
    channels: Tuple[str, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the result for persistence or transport."""

        return {
            "rule_id": self.rule.rule_id,
            "metric": self.rule.metric,
            "metric_value": self.metric_value,
            "comparison": self.rule.comparison.value,
            "threshold": self.rule.threshold,
            "severity": self.severity.value,
            "channels": list(self.channels),
            "message": self.message,
            "triggered_at": self.triggered_at.isoformat(),
            "metadata": dict(self.metadata),
        }
