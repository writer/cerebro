#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
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


@dataclass(frozen=True)
class BackfillRun:
    stack_file: str
    mode: str
    requested_runtime_ids: list[str]
    target_concurrency: int
    run_page_limit: int
    run_graph_page_limit: int
    run_event_limit: int
    wait_timeout_seconds: int
    run_attempt_timeout_seconds: int
    stop_running_before_run: bool
    targets: list[BackfillTarget]
    commands: list[list[str]]
    plan_hash: str


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


def _disabled_runtime_map(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    mapped: dict[str, dict[str, Any]] = {}
    entries = config.get("temporarilyDisabledSourceRuntimes") or []
    if not isinstance(entries, list):
        return mapped
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        runtime_id = str(entry.get("runtimeId") or entry.get("runtime_id") or entry.get("sourceRuntimeId") or "").strip()
        if runtime_id:
            mapped[runtime_id] = entry
    return mapped


def plan_backfill(config: dict[str, Any], runtime_ids: list[str], source_id: str = "") -> list[BackfillTarget]:
    runtimes = _runtime_map(config)
    disabled = _disabled_runtime_map(config)
    schedules = _schedule_map(config)
    targets: list[BackfillTarget] = []
    for runtime_id in _dedupe(runtime_ids):
        disabled_entry = disabled.get(runtime_id)
        if disabled_entry is not None:
            reason = str(disabled_entry.get("reason") or "temporarily disabled").strip()
            if review_deadline := str(disabled_entry.get("reviewDeadline") or "").strip():
                reason = f"{reason}; review_deadline={review_deadline}"
            targets.append(BackfillTarget(runtime_id, "", "", "", "", "quarantined", reason))
            continue
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
    if args.wait_timeout_seconds:
        command.extend(["--wait-timeout-seconds", str(args.wait_timeout_seconds)])
    if args.run_attempt_timeout_seconds:
        command.extend(["--run-attempt-timeout-seconds", str(args.run_attempt_timeout_seconds)])
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
    for command in _commands(args, targets):
        print(json.dumps(command))


def _command_groups(args: argparse.Namespace, targets: list[BackfillTarget]) -> list[tuple[str, list[str]]]:
    groups: list[tuple[str, list[str]]] = []
    for source_id, runtime_ids in _group_backfillable(targets).items():
        runtime_groups = [[runtime_id] for runtime_id in runtime_ids] if args.target_concurrency == 1 else [runtime_ids]
        groups.extend((source_id, runtime_group) for runtime_group in runtime_groups)
    return groups


def _commands(args: argparse.Namespace, targets: list[BackfillTarget]) -> list[list[str]]:
    return [_verify_command(args, source_id, runtime_ids) for source_id, runtime_ids in _command_groups(args, targets)]


def _plan_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def backfill_run(args: argparse.Namespace, runtime_ids: list[str], targets: list[BackfillTarget]) -> BackfillRun:
    commands = _commands(args, targets)
    hash_payload = {
        "stack_file": str(args.stack_file),
        "requested_runtime_ids": runtime_ids,
        "target_concurrency": args.target_concurrency,
        "run_page_limit": args.run_page_limit,
        "run_graph_page_limit": args.run_graph_page_limit,
        "run_event_limit": args.run_event_limit,
        "wait_timeout_seconds": args.wait_timeout_seconds,
        "run_attempt_timeout_seconds": args.run_attempt_timeout_seconds,
        "stop_running_before_run": args.stop_running_before_run,
        "targets": [asdict(target) for target in targets],
    }
    payload = {"mode": args.mode, "commands": commands, **hash_payload}
    return BackfillRun(plan_hash=_plan_hash(hash_payload), **payload)


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
    parser.add_argument("--format", choices=["tsv", "json", "commands", "run-json"], default="tsv")
    parser.add_argument("--target-concurrency", type=int, default=4)
    parser.add_argument("--run-page-limit", type=int, default=0)
    parser.add_argument("--run-graph-page-limit", type=int, default=0)
    parser.add_argument("--run-event-limit", type=int, default=0)
    parser.add_argument("--wait-timeout-seconds", type=int, default=0)
    parser.add_argument("--run-attempt-timeout-seconds", type=int, default=0)
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
    elif args.format == "run-json":
        print(json.dumps(asdict(backfill_run(args, runtime_ids, targets)), indent=2, sort_keys=True))
    else:
        _write_tsv(targets)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
