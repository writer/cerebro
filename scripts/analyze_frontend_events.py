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
from pathlib import Path
from typing import Iterable, Tuple

from cerebro.automation.telemetry_health import fetch_telemetry_health


def _parse_args() -> argparse.Namespace:
    """Parse CLI arguments for the telemetry analyzer."""
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


def _print_table(title: str, items: Iterable[Tuple[str, int]], limit: int = 10) -> None:
    """Render a simple bullet list of counts for console output."""
    rows = list(items)[:limit]
    if not rows:
        print(f"- {title}: (none)")
        return
    print(f"- {title}:")
    for key, count in rows:
        print(f"    • {key or '(none)'} — {count}")


async def _run(args: argparse.Namespace) -> int:
    """Execute the telemetry analysis using parsed CLI arguments."""
    summary = await fetch_telemetry_health(args.window_days)

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
            json.dump(summary.to_dict(), handle, indent=2, sort_keys=True)
        print(f"\nReport written to {args.output}")

    return 0


def main() -> int:
    """Entrypoint used by ``python scripts/analyze_frontend_events.py``."""
    args = _parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
