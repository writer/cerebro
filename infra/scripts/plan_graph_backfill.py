#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import shlex
import sys
from typing import Any

try:
    from aws.source_runtime_scope import load_cerebro_config, runtime_family, runtime_id_from_command, runtime_source_id
except ModuleNotFoundError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from aws.source_runtime_scope import load_cerebro_config, runtime_family, runtime_id_from_command, runtime_source_id


@dataclass(frozen=True)
class BackfillTarget:
    runtime_id: str
    source_id: str
    family: str
    schedule_name: str
    schedule_expression: str
    state: str
    reason: str


def _runtime_ids_from_text(text: str) -> list[str]:
    values: list[str] = []
    for line in text.splitlines():
        for part in re.split(r"[\s,]+", line.strip()):
            part = part.strip()
            if part:
                values.append(part)
    return values


def _missing_runtime_ids_from_diagnostics(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(
        r"missing graph ingest run history for \d+ declared runtime\(s\): (.*?)(?:; latest graph ingest run failed|$)",
        text,
        flags=re.IGNORECASE,
    ):
        values.extend(_runtime_ids_from_text(match.group(1)))
    return _dedupe(values)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _schedule_map(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    mapped: dict[str, dict[str, Any]] = {}
    for schedule in config.get("orchestratorSchedules") or []:
        if not isinstance(schedule, dict):
            continue
        runtime_id = runtime_id_from_command(schedule.get("command"))
        if runtime_id:
            mapped[runtime_id] = schedule
    return mapped


def _runtime_map(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    mapped: dict[str, dict[str, Any]] = {}
    for runtime in config.get("sourceRuntimes") or []:
        if not isinstance(runtime, dict):
            continue
        runtime_id = str(runtime.get("id") or "").strip()
        if runtime_id:
            mapped[runtime_id] = runtime
    return mapped


def plan_backfill(config: dict[str, Any], runtime_ids: list[str], source_id: str = "") -> list[BackfillTarget]:
    runtimes = _runtime_map(config)
    schedules = _schedule_map(config)
    targets: list[BackfillTarget] = []
    for runtime_id in _dedupe(runtime_ids):
        runtime = runtimes.get(runtime_id)
        if runtime is None:
            targets.append(BackfillTarget(runtime_id, "", "", "", "", "not_declared", "runtime is not declared in stack config"))
            continue
        runtime_source = runtime_source_id(runtime)
        if source_id and runtime_source != source_id:
            targets.append(BackfillTarget(runtime_id, runtime_source, runtime_family(runtime), "", "", "skipped", "source_id filter mismatch"))
            continue
        schedule = schedules.get(runtime_id)
        schedule_name = str((schedule or {}).get("name") or "").strip()
        schedule_expression = str((schedule or {}).get("scheduleExpression") or "").strip()
        if not schedule:
            state = "manual_backfill"
            reason = "runtime is declared without an orchestrator schedule"
        else:
            state = "backfillable"
            reason = "runtime is declared and scheduled"
        targets.append(
            BackfillTarget(
                runtime_id,
                runtime_source,
                runtime_family(runtime),
                schedule_name,
                schedule_expression,
                state,
                reason,
            )
        )
    return targets


def _group_backfillable(targets: list[BackfillTarget]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for target in targets:
        if target.state in {"backfillable", "manual_backfill"} and target.source_id:
            grouped[target.source_id].append(target.runtime_id)
    return dict(sorted(grouped.items()))


def _verify_command(args: argparse.Namespace, source_id: str, runtime_ids: list[str]) -> list[str]:
    command = [
        "uv",
        "run",
        "python",
        "scripts/verify_source_runtime_ecs.py",
        "--stack-file",
        str(args.stack_file),
        "--source-id",
        source_id,
        "--target-concurrency",
        str(args.target_concurrency),
        "--succeed-after-graph-ingest",
        "--allow-lease-contention-skip",
    ]
    if args.mode == "run":
        command.append("--run")
    elif args.mode == "dry-run":
        command.append("--dry-run")
    if args.run_page_limit:
        command.extend(["--run-page-limit", str(args.run_page_limit)])
    if args.run_graph_page_limit:
        command.extend(["--run-graph-page-limit", str(args.run_graph_page_limit)])
    if args.run_event_limit:
        command.extend(["--run-event-limit", str(args.run_event_limit)])
    if args.stop_running_before_run:
        command.append("--stop-running-before-run")
    for runtime_id in runtime_ids:
        command.extend(["--runtime-id", runtime_id])
    return command


def _write_tsv(targets: list[BackfillTarget]) -> None:
    print("runtime_id\tsource_id\tfamily\tschedule_name\tschedule_expression\tstate\treason")
    for target in targets:
        print("\t".join(str(value) for value in asdict(target).values()))


def _write_commands(args: argparse.Namespace, targets: list[BackfillTarget]) -> None:
    print("set -uo pipefail")
    print("status=0")
    for source_id, runtime_ids in _group_backfillable(targets).items():
        runtime_groups = [[runtime_id] for runtime_id in runtime_ids] if args.target_concurrency == 1 else [runtime_ids]
        for runtime_group in runtime_groups:
            command = _verify_command(args, source_id, runtime_group)
            print(" ".join(shlex.quote(part) for part in command) + " || status=$?")
    print('exit "${status}"')


def _load_runtime_ids(args: argparse.Namespace) -> list[str]:
    values = list(args.runtime_id or [])
    if args.runtime_id_file:
        if str(args.runtime_id_file) == "-":
            values.extend(_runtime_ids_from_text(sys.stdin.read()))
        else:
            values.extend(_runtime_ids_from_text(args.runtime_id_file.read_text(encoding="utf-8")))
    if args.diagnostics_file:
        values.extend(_missing_runtime_ids_from_diagnostics(args.diagnostics_file.read_text(encoding="utf-8", errors="replace")))
    return _dedupe(values)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plan graph source-runtime backfills from missing ingest history.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--runtime-id", action="append", default=[])
    parser.add_argument("--runtime-id-file", type=Path)
    parser.add_argument("--diagnostics-file", type=Path)
    parser.add_argument("--source-id", default="")
    parser.add_argument("--mode", choices=["plan", "dry-run", "run"], default="plan")
    parser.add_argument("--format", choices=["tsv", "json", "commands"], default="tsv")
    parser.add_argument("--target-concurrency", type=int, default=4)
    parser.add_argument("--run-page-limit", type=int, default=0)
    parser.add_argument("--run-graph-page-limit", type=int, default=0)
    parser.add_argument("--run-event-limit", type=int, default=0)
    parser.add_argument("--stop-running-before-run", action="store_true")
    args = parser.parse_args(argv)

    runtime_ids = _load_runtime_ids(args)
    if not runtime_ids:
        raise SystemExit("no runtime ids provided")
    config = load_cerebro_config(args.stack_file)
    targets = plan_backfill(config, runtime_ids, args.source_id)

    if args.format == "json":
        print(json.dumps([asdict(target) for target in targets], indent=2, sort_keys=True))
    elif args.format == "commands":
        _write_commands(args, targets)
    else:
        _write_tsv(targets)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
