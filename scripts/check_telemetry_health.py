"""Check telemetry health thresholds and optionally raise alerts."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from cerebro.automation.telemetry_health import (
    evaluate_health_thresholds,
    fetch_telemetry_health,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate frontend telemetry health metrics against thresholds",
    )
    parser.add_argument(
        "--window-days",
        type=int,
        default=7,
        help="Number of days to include in the analysis window",
    )
    parser.add_argument(
        "--max-missing-metadata",
        type=float,
        default=0.05,
        help="Maximum allowed ratio of events missing metadata",
    )
    parser.add_argument(
        "--max-missing-component",
        type=float,
        default=0.02,
        help="Maximum allowed ratio of events without component labels",
    )
    parser.add_argument(
        "--min-total-events",
        type=int,
        default=50,
        help="Minimum number of events expected in the window",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON file to write the snapshot report",
    )
    return parser.parse_args()


async def _run(args: argparse.Namespace) -> int:
    snapshot = await fetch_telemetry_health(args.window_days)

    print("Telemetry Health Check")
    print("======================")
    print(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True))

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        print(f"Snapshot written to {args.output}")

    issues = evaluate_health_thresholds(
        snapshot,
        max_missing_metadata_ratio=args.max_missing_metadata,
        max_missing_component_ratio=args.max_missing_component,
        min_total_events=args.min_total_events,
    )

    if issues:
        print("\nThreshold failures detected:")
        for issue in issues:
            print(f" - {issue}")
        return 1

    print("\nAll telemetry thresholds within acceptable ranges")
    return 0


def main() -> int:
    args = _parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
