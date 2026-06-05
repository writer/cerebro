#!/usr/bin/env python3
"""Run contract-governed Make targets and summarize every result."""

from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_TARGETS = [
    "proto-lint",
    "proto-generate-check",
    "proto-breaking",
    "openapi-check",
    "openapi-lint",
    "catalog-check",
    "detection-catalog-check",
    "docs-drift-check",
    "readme-check",
    "mcp-contract-check",
    "mcp-sdk-compat",
]


@dataclass(frozen=True)
class CheckResult:
    target: str
    exit_code: int
    duration_seconds: float


def run_target(target: str) -> CheckResult:
    print(f"\n==> make {target}", flush=True)
    started = time.monotonic()
    completed = subprocess.run(["make", target], cwd=ROOT, check=False)
    return CheckResult(
        target=target,
        exit_code=completed.returncode,
        duration_seconds=time.monotonic() - started,
    )


def print_summary(results: list[CheckResult]) -> None:
    print("\nContract check summary:")
    width = max(len(result.target) for result in results)
    for result in results:
        status = "PASS" if result.exit_code == 0 else "FAIL"
        print(f"  {status:<4}  {result.target:<{width}}  {result.duration_seconds:6.1f}s")


def main() -> int:
    results = [run_target(target) for target in CONTRACT_TARGETS]
    print_summary(results)
    return 1 if any(result.exit_code != 0 for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
