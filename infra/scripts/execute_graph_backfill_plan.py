#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


def _load_plan(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("backfill plan must be a JSON object")
    return loaded


def _commands(plan: dict[str, Any]) -> list[list[str]]:
    commands = plan.get("commands")
    if not isinstance(commands, list):
        raise ValueError("backfill plan missing commands array")
    normalized: list[list[str]] = []
    for index, command in enumerate(commands):
        if not isinstance(command, list) or not command or any(not isinstance(part, str) or not part for part in command):
            raise ValueError(f"command {index} must be a non-empty string array")
        normalized.append(command)
    return normalized


def execute_plan(plan: dict[str, Any], expected_plan_hash: str) -> int:
    mode = str(plan.get("mode") or "").strip()
    if mode == "plan":
        raise ValueError("plan mode cannot be executed")
    plan_hash = str(plan.get("plan_hash") or "").strip()
    expected_plan_hash = expected_plan_hash.strip()
    if not expected_plan_hash:
        raise ValueError("expected plan hash is required for dry-run and run modes")
    if plan_hash != expected_plan_hash:
        raise ValueError(f"plan hash mismatch: expected {expected_plan_hash}, got {plan_hash}")
    status = 0
    for command in _commands(plan):
        print(json.dumps({"event": "execute_backfill_command", "command": command}, sort_keys=True), flush=True)
        try:
            result = subprocess.run(command, check=False)
        except OSError as exc:
            print(str(exc), file=sys.stderr)
            status = 1
            continue
        if result.returncode != 0:
            status = result.returncode
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Execute a graph backfill run JSON plan without shell eval.")
    parser.add_argument("plan_file", type=Path)
    parser.add_argument("--expected-plan-hash", required=True)
    args = parser.parse_args(argv)
    return execute_plan(_load_plan(args.plan_file), args.expected_plan_hash)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
