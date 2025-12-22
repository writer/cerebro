"""Rule evaluation for telemetry alerting."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Dict, Optional, Protocol, Sequence

from .results import AlertResult
from .rules import AlertRule, RuleComparison
from ..telemetry_health import TelemetryHealthSnapshot


class AlertCooldownStore(Protocol):
    """Storage backend responsible for cooldown checks and recording alerts."""

    async def should_suppress(
        self,
        rule: AlertRule,
        *,
        now: datetime,
    ) -> bool:
        """Return True if the alert should be suppressed due to cooldown."""

    async def record_fire(
        self,
        result: AlertResult,
    ) -> None:
        """Persist metadata about a fired alert."""


MetricAccessor = Callable[[TelemetryHealthSnapshot], float]


def _build_metric_accessors() -> Dict[str, MetricAccessor]:
    return {
        "total_events": lambda snap: float(snap.total_events),
        "unique_orgs": lambda snap: float(snap.unique_orgs),
        "unique_users": lambda snap: float(snap.unique_users),
        "unique_sessions": lambda snap: float(snap.unique_sessions),
        "missing_metadata_ratio": lambda snap: snap.missing_metadata_ratio(),
        "missing_component_ratio": lambda snap: snap.missing_component_ratio(),
        "average_events_per_session": lambda snap: float(
            snap.average_events_per_session
        ),
    }


_METRIC_ACCESSORS = _build_metric_accessors()


def _resolve_metric(snapshot: TelemetryHealthSnapshot, metric: str) -> float:
    if metric in _METRIC_ACCESSORS:
        return _METRIC_ACCESSORS[metric](snapshot)

    if metric.startswith("events_by_type."):
        _, event_type = metric.split(".", 1)
        return float(snapshot.events_by_type.get(event_type, 0))

    if metric.startswith("events_by_component."):
        _, component = metric.split(".", 1)
        return float(snapshot.events_by_component.get(component, 0))

    raise KeyError(f"Unsupported metric '{metric}'")


def _compare(value: float, threshold: float, comparison: RuleComparison) -> bool:
    if comparison is RuleComparison.GREATER_THAN:
        return value > threshold
    if comparison is RuleComparison.GREATER_THAN_OR_EQUAL:
        return value >= threshold
    if comparison is RuleComparison.LESS_THAN:
        return value < threshold
    if comparison is RuleComparison.LESS_THAN_OR_EQUAL:
        return value <= threshold
    raise ValueError(f"Unhandled comparison {comparison}")  # pragma: no cover


async def evaluate_rules(
    snapshot: TelemetryHealthSnapshot,
    rules: Sequence[AlertRule],
    *,
    cooldown_store: Optional[AlertCooldownStore] = None,
    now: Optional[datetime] = None,
) -> Sequence[AlertResult]:
    """Evaluate rules against a snapshot, returning fired alerts."""

    current_time = now or datetime.now(timezone.utc)
    fired: list[AlertResult] = []

    for rule in rules:
        try:
            metric_value = _resolve_metric(snapshot, rule.metric)
        except KeyError:
            continue

        if not _compare(metric_value, rule.threshold, rule.comparison):
            continue

        if rule.cooldown_minutes > 0 and cooldown_store is not None:
            suppress = await cooldown_store.should_suppress(rule, now=current_time)
            if suppress:
                continue

        result = AlertResult(
            rule=rule,
            metric_value=metric_value,
            triggered_at=current_time,
            message=rule.format_message(metric_value),
            severity=rule.severity,
            channels=rule.channels,
            metadata={
                "threshold": rule.threshold,
                "comparison": rule.comparison.value,
            },
        )

        fired.append(result)

        if cooldown_store is not None:
            await cooldown_store.record_fire(result)

    return fired
