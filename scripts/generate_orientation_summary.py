"""Produce orientation analytics from telemetry for dashboards and agents.

The summary highlights trending event types/components by comparing a primary
observation window to an earlier baseline.  Results may be consumed by FE
dashboards or agents when suggesting next-best-actions.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from sqlalchemy import and_, func, select

from cerebro.core.database import async_session_factory
from cerebro.core.models import FrontendObservationEvent


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate orientation summaries from frontend telemetry"
    )
    parser.add_argument(
        "--window-hours",
        type=int,
        default=24,
        help="Observation window in hours for the primary period",
    )
    parser.add_argument(
        "--baseline-hours",
        type=int,
        default=168,
        help="Baseline window length in hours immediately preceding the observation window",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON file for summary output",
    )
    return parser.parse_args()


async def _count_events_between(start: datetime, end: datetime) -> Dict[str, int]:
    stmt = (
        select(FrontendObservationEvent.event_type, func.count())
        .where(
            FrontendObservationEvent.occurred_at >= start,
            FrontendObservationEvent.occurred_at < end,
        )
        .group_by(FrontendObservationEvent.event_type)
    )
    async with async_session_factory() as session:
        results = await session.execute(stmt)
        return {etype or "(unknown)": count for etype, count in results}


async def _component_counts(start: datetime, end: datetime) -> Dict[str, int]:
    stmt = (
        select(FrontendObservationEvent.component, func.count())
        .where(
            FrontendObservationEvent.occurred_at >= start,
            FrontendObservationEvent.occurred_at < end,
        )
        .group_by(FrontendObservationEvent.component)
    )
    async with async_session_factory() as session:
        results = await session.execute(stmt)
        return {component or "(unknown)": count for component, count in results}


def _delta(current: Dict[str, int], baseline: Dict[str, int]) -> List[Tuple[str, int, int, float]]:
    rows: List[Tuple[str, int, int, float]] = []
    for key, count in current.items():
        baseline_count = baseline.get(key, 0)
        delta = count - baseline_count
        pct = ((count - baseline_count) / baseline_count * 100.0) if baseline_count else 100.0
        rows.append((key, count, baseline_count, pct))
    rows.sort(key=lambda x: x[3], reverse=True)
    return rows


async def generate_orientation_summary(
    window_hours: int,
    baseline_hours: int,
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=window_hours)
    baseline_start = window_start - timedelta(hours=baseline_hours)

    current_types = await _count_events_between(window_start, now)
    baseline_types = await _count_events_between(baseline_start, window_start)

    current_components = await _component_counts(window_start, now)
    baseline_components = await _component_counts(baseline_start, window_start)

    trending_types = _delta(current_types, baseline_types)
    trending_components = _delta(current_components, baseline_components)

    summary = {
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
        "top_event_types": [
            {
                "event_type": key,
                "current_count": current,
                "baseline_count": baseline,
                "percent_change": round(pct, 2),
            }
            for key, current, baseline, pct in trending_types[:10]
        ],
        "top_components": [
            {
                "component": key,
                "current_count": current,
                "baseline_count": baseline,
                "percent_change": round(pct, 2),
            }
            for key, current, baseline, pct in trending_components[:10]
        ],
        "total_events_current": sum(current_types.values()),
        "total_events_baseline": sum(baseline_types.values()),
    }

    return summary


async def _run(args: argparse.Namespace) -> int:
    summary = await generate_orientation_summary(args.window_hours, args.baseline_hours)

    print("Orientation Summary")
    print("====================")
    print(f"Window  : {summary['window']['start']} → {summary['window']['end']}")
    print(f"Baseline: {summary['baseline']['start']} → {summary['baseline']['end']}")
    print(f"Total events (window): {summary['total_events_current']}")
    print(f"Total events (base)  : {summary['total_events_baseline']}")
    print("\nTop event types by growth:")
    for row in summary["top_event_types"]:
        print(
            f" - {row['event_type']}: {row['current_count']} (baseline {row['baseline_count']}, Δ%={row['percent_change']})"
        )
    print("\nTop components by growth:")
    for row in summary["top_components"]:
        print(
            f" - {row['component']}: {row['current_count']} (baseline {row['baseline_count']}, Δ%={row['percent_change']})"
        )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"\nSummary written to {args.output}")

    return 0


def main() -> int:
    args = _parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
