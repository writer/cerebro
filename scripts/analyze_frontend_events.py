"""Utility to validate frontend observation telemetry signal quality.

The script aggregates metrics from ``frontend_observation_events`` to help
dashboard backfilling and automated QA.  It reports key health indicators for
the chosen time window and can optionally emit a JSON document for downstream
dashboards.

Usage examples::

    uv run python scripts/analyze_frontend_events.py --window-days 7
    uv run python scripts/analyze_frontend_events.py --output telemetry.json

The script relies on the standard Cerebro settings module for database access,
so ensure the relevant ``DATABASE_URL`` / ``ENVIRONMENT`` variables are set.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import func, select

from cerebro.core.database import async_session_factory
from cerebro.core.models import FrontendObservationEvent


@dataclass
class TelemetryHealthSummary:
    """Structured snapshot of telemetry signal quality metrics."""

    generated_at: datetime
    window_start: Optional[datetime]
    window_end: datetime
    total_events: int
    unique_orgs: int
    unique_users: int
    unique_sessions: int
    events_by_type: Dict[str, int]
    events_by_component: Dict[str, int]
    missing_component: int
    missing_metadata: int
    empty_context: int
    average_events_per_session: float
    recent_events: List[Dict[str, Any]]

    def to_json(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["generated_at"] = self.generated_at.isoformat()
        if self.window_start:
            payload["window_start"] = self.window_start.isoformat()
        payload["window_end"] = self.window_end.isoformat()
        return payload


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aggregate frontend observation telemetry signal quality metrics"
    )
    parser.add_argument(
        "--window-days",
        type=int,
        default=7,
        help="Number of days in the past to include in the analysis (0 = all data)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write the JSON summary report",
    )
    parser.add_argument(
        "--print-samples",
        action="store_true",
        help="Print a table of the most recent telemetry events",
    )
    return parser.parse_args()


async def _fetch_summary(window_days: int) -> TelemetryHealthSummary:
    now = datetime.now(timezone.utc)
    window_start: Optional[datetime] = None
    filters: List[Any] = []

    if window_days > 0:
        window_start = now - timedelta(days=window_days)
        filters.append(FrontendObservationEvent.occurred_at >= window_start)

    async with async_session_factory() as session:
        base_query = select(func.count()).select_from(FrontendObservationEvent)
        if filters:
            base_query = base_query.where(*filters)
        total_events = (await session.execute(base_query)).scalar_one()

        events_by_type = await session.execute(
            select(
                FrontendObservationEvent.event_type,
                func.count(),
            )
            .where(*filters)
            .group_by(FrontendObservationEvent.event_type)
            .order_by(func.count().desc())
        )
        by_type_counter = {etype or "(unknown)": count for etype, count in events_by_type}

        events_by_component = await session.execute(
            select(
                FrontendObservationEvent.component,
                func.count(),
            )
            .where(*filters)
            .group_by(FrontendObservationEvent.component)
            .order_by(func.count().desc())
        )
        by_component_counter = {
            component or "(none)": count for component, count in events_by_component
        }

        unique_orgs = (
            await session.execute(
                select(func.count(func.distinct(FrontendObservationEvent.org_id))).where(
                    *filters
                )
            )
        ).scalar_one()

        unique_users = (
            await session.execute(
                select(func.count(func.distinct(FrontendObservationEvent.user_id))).where(
                    *filters
                )
            )
        ).scalar_one()

        unique_sessions = (
            await session.execute(
                select(
                    func.count(
                        func.distinct(FrontendObservationEvent.agent_session_id)
                    )
                ).where(*filters)
            )
        ).scalar_one()

        missing_component = (
            await session.execute(
                select(func.count())
                .select_from(FrontendObservationEvent)
                .where(FrontendObservationEvent.component.is_(None), *filters)
            )
        ).scalar_one()

        missing_metadata = (
            await session.execute(
                select(func.count())
                .select_from(FrontendObservationEvent)
                .where(FrontendObservationEvent.event_metadata.is_(None), *filters)
            )
        ).scalar_one()

        empty_context = (
            await session.execute(
                select(func.count())
                .select_from(FrontendObservationEvent)
                .where(FrontendObservationEvent.context_data == {}, *filters)
            )
        ).scalar_one()

        events_per_session = (total_events / unique_sessions) if unique_sessions else 0.0

        recent_stmt = (
            select(FrontendObservationEvent)
            .where(*filters)
            .order_by(FrontendObservationEvent.occurred_at.desc())
            .limit(20)
        )
        recent_rows = (await session.execute(recent_stmt)).scalars().all()
        recent_events: List[Dict[str, Any]] = [
            {
                "event_id": str(row.event_id),
                "occurred_at": row.occurred_at.isoformat() if row.occurred_at else None,
                "event_type": row.event_type,
                "component": row.component,
                "org_id": str(row.org_id) if row.org_id else None,
                "user_id": str(row.user_id) if row.user_id else None,
                "agent_session_id": str(row.agent_session_id)
                if row.agent_session_id
                else None,
                "metadata_keys": sorted((row.event_metadata or {}).keys()),
            }
            for row in recent_rows
        ]

    return TelemetryHealthSummary(
        generated_at=now,
        window_start=window_start,
        window_end=now,
        total_events=total_events,
        unique_orgs=unique_orgs,
        unique_users=unique_users,
        unique_sessions=unique_sessions,
        events_by_type=by_type_counter,
        events_by_component=by_component_counter,
        missing_component=missing_component,
        missing_metadata=missing_metadata,
        empty_context=empty_context,
        average_events_per_session=round(events_per_session, 2),
        recent_events=recent_events,
    )


def _print_table(title: str, items: Iterable[tuple[str, int]], limit: int = 10) -> None:
    rows = list(items)[:limit]
    if not rows:
        print(f"- {title}: (none)")
        return
    print(f"- {title}:")
    for key, count in rows:
        print(f"    • {key or '(none)'} — {count}")


async def _run(args: argparse.Namespace) -> int:
    summary = await _fetch_summary(args.window_days)

    print("Telemetry Signal Health Summary")
    print("==============================")
    if summary.window_start:
        print(
            f"Window       : {summary.window_start.isoformat()} → {summary.window_end.isoformat()}"
        )
    else:
        print(f"Window       : all history → {summary.window_end.isoformat()}")
    print(f"Generated    : {summary.generated_at.isoformat()}")
    print(f"Total events : {summary.total_events}")
    print(f"Unique orgs  : {summary.unique_orgs}")
    print(f"Unique users : {summary.unique_users}")
    print(f"Sessions     : {summary.unique_sessions}")
    print(f"Avg/session  : {summary.average_events_per_session}")
    print(f"Missing component labels : {summary.missing_component}")
    print(f"Missing metadata payloads: {summary.missing_metadata}")
    print(f"Empty context payloads  : {summary.empty_context}")

    _print_table("Top event types", summary.events_by_type.items())
    _print_table("Top components", summary.events_by_component.items())

    if args.print_samples:
        print("\nRecent telemetry samples:")
        for event in summary.recent_events:
            print(
                f" - {event['occurred_at']} | {event['event_type']} | {event['component']} | "
                f"org={event['org_id']} user={event['user_id']} session={event['agent_session_id']}"
            )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(summary.to_json(), handle, indent=2, sort_keys=True)
        print(f"\nReport written to {args.output}")

    return 0


def main() -> int:
    args = _parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
