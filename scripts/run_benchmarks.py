"""Run deterministic benchmark suites and emit CI-friendly scorecards."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cerebro.agents.benchmarks import BenchmarkRunner, load_benchmark_cases


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Cerebro benchmark suites")
    parser.add_argument(
        "--cases-dir",
        type=Path,
        default=Path("benchmarks/cases"),
        help="Directory containing benchmark case definitions",
    )
    parser.add_argument(
        "--scorecard",
        type=Path,
        default=Path("benchmarks/results/scorecard.json"),
        help="Where to write the JSON scorecard",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Exit with non-zero status when any case fails",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    cases = load_benchmark_cases(args.cases_dir)
    if not cases:
        print(f"No benchmark cases found in {args.cases_dir}")
        return 0

    runner = BenchmarkRunner(cases)
    result = runner.run()
    scorecard = result.scorecard()

    args.scorecard.parent.mkdir(parents=True, exist_ok=True)
    with args.scorecard.open("w", encoding="utf-8") as handle:
        json.dump(scorecard, handle, indent=2, sort_keys=True)

    passed_cases = [
        case_id for case_id, metrics in scorecard.items() if metrics["passed"]
    ]
    failed_cases = [
        case_id for case_id, metrics in scorecard.items() if not metrics["passed"]
    ]

    print(f"Benchmarks completed: {len(scorecard)} cases")
    print(f"  Passed: {', '.join(passed_cases) or 'none'}")
    if failed_cases:
        print(f"  Failed: {', '.join(failed_cases)}")

    if failed_cases and args.fail_on_error:
        print("Benchmark failures detected")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
