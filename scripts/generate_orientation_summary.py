"""Produce orientation analytics from telemetry for dashboards and agents.

The summary highlights trending event types/components by comparing a primary
observation window to an earlier baseline.  Results may be consumed by FE
dashboards or agents when suggesting next-best-actions.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from cerebro.analytics.orientation import generate_orientation_summary


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
