"""Utilities for generating orientation analytics from telemetry.

This module powers both dashboard widgets and agent-facing tooling.  Given an
observation window and a baseline window it produces aggregates showing which
frontend telemetry signals are trending up or down.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy import func, select

from cerebro.core.database import async_session_factory
from cerebro.core.models import FrontendObservationEvent


@dataclass
class TrendingRow:
    key: str
    current_count: int
    baseline_count: int
    percent_change: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "current_count": self.current_count,
            "baseline_count": self.baseline_count,
            "percent_change": round(self.percent_change, 2),
        }


async def _count_by_field(field, start: datetime, end: datetime) -> Dict[str, int]:
    """Return counts grouped by ``field`` between ``start`` and ``end``."""

    stmt = (
        select(field, func.count())
        .where(FrontendObservationEvent.occurred_at >= start)
        .where(FrontendObservationEvent.occurred_at < end)
        .group_by(field)
    )
    async with async_session_factory() as session:
        rows = await session.execute(stmt)
        return {value or "(unknown)": count for value, count in rows}


def _diff(current: Dict[str, int], baseline: Dict[str, int]) -> List[TrendingRow]:
    """Compute delta values between current and baseline counts."""

    rows: List[TrendingRow] = []
    for key, count in current.items():
        baseline_count = baseline.get(key, 0)
        if baseline_count:
            pct = (count - baseline_count) / baseline_count * 100.0
        else:
            pct = 100.0 if count else 0.0
        rows.append(TrendingRow(key, count, baseline_count, pct))
    rows.sort(key=lambda row: row.percent_change, reverse=True)
    return rows


async def generate_orientation_summary(
    window_hours: int,
    baseline_hours: int,
    top_n: int = 10,
) -> Dict[str, Any]:
    """Compute orientation analytics for the given window and baseline."""

    if window_hours <= 0:
        raise ValueError("window_hours must be positive")
    if baseline_hours <= 0:
        raise ValueError("baseline_hours must be positive")

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=window_hours)
    baseline_start = window_start - timedelta(hours=baseline_hours)

    current_types, baseline_types = await asyncio.gather(  # type: ignore[name-defined]
        _count_by_field(FrontendObservationEvent.event_type, window_start, now),
        _count_by_field(FrontendObservationEvent.event_type, baseline_start, window_start),
    )

    current_components, baseline_components = await asyncio.gather(  # type: ignore[name-defined]
        _count_by_field(FrontendObservationEvent.component, window_start, now),
        _count_by_field(FrontendObservationEvent.component, baseline_start, window_start),
    )

    trending_types = _diff(current_types, baseline_types)
    trending_components = _diff(current_components, baseline_components)

    return {
        "generated_at": now.isoformat(),
        "window": {
            "start": window_start.isoformat(),
            "end": now.isoformat(),
            "hours": window_hours,
        },
        "baseline": {
            "start": baseline_start.isoformat(),
            "end": window_start.isoformat(),
            "hours": baseline_hours,
        },
        "total_events_current": sum(current_types.values()),
        "total_events_baseline": sum(baseline_types.values()),
        "top_event_types": [row.to_dict() for row in trending_types[:top_n]],
        "top_components": [row.to_dict() for row in trending_components[:top_n]],
    }


__all__ = ["generate_orientation_summary"]
