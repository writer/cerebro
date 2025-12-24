"""Service helpers for telemetry alerting orchestration."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from ..telemetry_health import TelemetryHealthSnapshot, fetch_telemetry_health
from .config import rules_from_env
from .evaluator import AlertCooldownStore, evaluate_rules
from .results import AlertResult
from .rules import AlertRule


async def collect_telemetry_alerts(
    *,
    window_days: int = 7,
    rules: Sequence[AlertRule] | None = None,
    cooldown_store: AlertCooldownStore | None = None,
    db_session: AsyncSession | None = None,
) -> tuple[tuple[AlertResult, ...], TelemetryHealthSnapshot]:
    """Fetch telemetry snapshot and evaluate rules, returning alerts and snapshot."""

    applied_rules = tuple(rules or rules_from_env())
    snapshot = await fetch_telemetry_health(window_days, db_session=db_session)
    results = await evaluate_rules(
        snapshot, applied_rules, cooldown_store=cooldown_store
    )
    return tuple(results), snapshot
