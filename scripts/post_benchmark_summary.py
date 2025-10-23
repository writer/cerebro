"""Post benchmark scorecard summaries to Slack and control regression signals."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import httpx

from cerebro.automation.benchmark_summary import (
    BenchmarkSummary,
    build_slack_payload,
    load_benchmark_summary,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send benchmark scorecard summaries to Slack",
    )
    parser.add_argument(
        "--scorecard",
        type=Path,
        default=Path("benchmarks/results/scorecard.json"),
        help="Path to the benchmark scorecard JSON",
    )
    parser.add_argument(
        "--slack-webhook",
        help="Slack webhook URL to post the summary",
    )
    parser.add_argument(
        "--run-url",
        help="Optional link to the CI run or dashboard",
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Return a non-zero exit code when any benchmark case fails",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON output for the computed summary",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip Slack delivery and only print the payload",
    )
    return parser.parse_args()


async def _send_slack(webhook: str, payload: dict[str, object]) -> None:
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(webhook, json=payload)
        response.raise_for_status()


async def _run(args: argparse.Namespace) -> int:
    summary = load_benchmark_summary(args.scorecard)

    print("Benchmark Summary")
    print("=================")
    print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        print(f"Summary written to {args.output}")

    if args.slack_webhook:
        payload = build_slack_payload(summary, run_url=args.run_url)
        if args.dry_run:
            print("Dry run enabled; Slack payload not sent")
            print(json.dumps(payload, indent=2))
        else:
            await _send_slack(args.slack_webhook, payload)
            print("Slack notification delivered")

    if args.fail_on_regression and summary.has_failures:
        print("Benchmark regressions detected; failing per configuration")
        return 1

    return 0


def main() -> int:
    args = _parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
