#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

try:
    from aws.source_runtime_scope import (
        load_cerebro_config,
        runtime_family,
        runtime_ids_from_command,
        runtime_source_id,
    )
    from scripts.graph_backfill_contract import (
        EXECUTABLE_TARGET_STATES,
        PLAN_SCHEMA_VERSION,
        compute_plan_hash,
        file_sha256,
        validate_plan,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from aws.source_runtime_scope import (
        load_cerebro_config,
        runtime_family,
        runtime_ids_from_command,
        runtime_source_id,
    )
    from scripts.graph_backfill_contract import (
        EXECUTABLE_TARGET_STATES,
        PLAN_SCHEMA_VERSION,
        compute_plan_hash,
        file_sha256,
        validate_plan,
    )


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
class BackfillPolicy:
    max_targets: int
    max_targets_per_source: int
    source_parallelism: int
    source_cooldown_seconds: int
    max_attempts: int
    retry_backoff_seconds: int
    run_page_limit: int
    run_graph_page_limit: int
    run_event_limit: int
    wait_timeout_seconds: int
    run_attempt_timeout_seconds: int
    stop_running_before_run: bool


@dataclass(frozen=True)
class BackfillSourceGroup:
    source_id: str
    source_key: str
    runtime_ids: list[str]


@dataclass(frozen=True)
class BackfillRun:
    schema_version: int
    control_plane_ref: str
    stack_file: str
    stack_name: str
    stack_config_sha256: str
    mode: str
    requested_runtime_ids: list[str]
    policy: BackfillPolicy
    targets: list[BackfillTarget]
    source_groups: list[BackfillSourceGroup]
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
        r"missing graph ingest run history for \d+ declared runtime\(s\): ([^\n;]+)",
        text,
        flags=re.IGNORECASE,
    ):
        values.extend(_runtime_ids_from_text(match.group(1)))
    return _dedupe(values)


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _schedule_map(config: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    mapped: dict[str, list[dict[str, Any]]] = {}
    for schedule in config.get("orchestratorSchedules") or []:
        if not isinstance(schedule, dict):
            continue
        for runtime_id in runtime_ids_from_command(schedule.get("command")):
            mapped.setdefault(runtime_id, []).append(schedule)
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
        runtime_id = str(
            entry.get("runtimeId")
            or entry.get("runtime_id")
            or entry.get("sourceRuntimeId")
            or ""
        ).strip()
        if runtime_id:
            mapped[runtime_id] = entry
    return mapped


def plan_backfill(
    config: dict[str, Any], runtime_ids: list[str], source_id: str = ""
) -> list[BackfillTarget]:
    runtimes = _runtime_map(config)
    disabled = _disabled_runtime_map(config)
    schedules = _schedule_map(config)
    targets: list[BackfillTarget] = []
    for runtime_id in sorted(_dedupe(runtime_ids)):
        disabled_entry = disabled.get(runtime_id)
        if disabled_entry is not None:
            reason = str(disabled_entry.get("reason") or "temporarily disabled").strip()
            if review_deadline := str(
                disabled_entry.get("reviewDeadline") or ""
            ).strip():
                reason = f"{reason}; review_deadline={review_deadline}"
            targets.append(
                BackfillTarget(runtime_id, "", "", "", "", "quarantined", reason)
            )
            continue
        runtime = runtimes.get(runtime_id)
        if runtime is None:
            targets.append(
                BackfillTarget(
                    runtime_id,
                    "",
                    "",
                    "",
                    "",
                    "not_declared",
                    "runtime is not declared in stack config",
                )
            )
            continue
        runtime_source = runtime_source_id(runtime)
        if source_id and runtime_source != source_id:
            targets.append(
                BackfillTarget(
                    runtime_id,
                    runtime_source,
                    runtime_family(runtime),
                    "",
                    "",
                    "skipped",
                    "source_id filter mismatch",
                )
            )
            continue
        runtime_schedules = schedules.get(runtime_id) or []
        schedule = runtime_schedules[0] if len(runtime_schedules) == 1 else None
        schedule_name = str((schedule or {}).get("name") or "").strip()
        schedule_expression = str(
            (schedule or {}).get("scheduleExpression") or ""
        ).strip()
        if not runtime_schedules:
            state = "missing_schedule"
            reason = "runtime is declared without an orchestrator schedule"
        elif len(runtime_schedules) > 1:
            state = "ambiguous_schedule"
            reason = f"runtime is declared in {len(runtime_schedules)} orchestrator schedules"
        elif (
            str((schedule or {}).get("state") or "ENABLED").strip().upper()
            == "DISABLED"
        ):
            state = "schedule_disabled"
            reason = "runtime orchestrator schedule is disabled"
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


def _source_key(source_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", source_id.lower()).strip("-")[:40] or "source"
    digest = hashlib.sha256(source_id.encode("utf-8")).hexdigest()[:10]
    return f"{slug}-{digest}"


def _source_groups(targets: list[BackfillTarget]) -> list[BackfillSourceGroup]:
    grouped: dict[str, list[str]] = {}
    for target in targets:
        if target.state in EXECUTABLE_TARGET_STATES and target.source_id:
            grouped.setdefault(target.source_id, []).append(target.runtime_id)
    return [
        BackfillSourceGroup(source_id, _source_key(source_id), sorted(runtime_ids))
        for source_id, runtime_ids in sorted(grouped.items())
    ]


def _policy(args: argparse.Namespace) -> BackfillPolicy:
    return BackfillPolicy(
        max_targets=args.max_targets,
        max_targets_per_source=args.max_targets_per_source,
        source_parallelism=args.source_parallelism,
        source_cooldown_seconds=args.source_cooldown_seconds,
        max_attempts=args.max_attempts,
        retry_backoff_seconds=args.retry_backoff_seconds,
        run_page_limit=args.run_page_limit,
        run_graph_page_limit=args.run_graph_page_limit,
        run_event_limit=args.run_event_limit,
        wait_timeout_seconds=args.wait_timeout_seconds,
        run_attempt_timeout_seconds=args.run_attempt_timeout_seconds,
        stop_running_before_run=args.stop_running_before_run,
    )


def _stack_name(stack_file: Path) -> str:
    name = stack_file.name
    if name.startswith("Pulumi.") and name.endswith(".yaml"):
        return name.removeprefix("Pulumi.").removesuffix(".yaml")
    return stack_file.stem


def _control_plane_ref(explicit: str) -> str:
    if explicit.strip():
        return explicit.strip()
    if github_sha := os.environ.get("GITHUB_SHA", "").strip():
        return github_sha
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "local-uncommitted"
    return completed.stdout.strip() or "local-uncommitted"


def backfill_run(
    args: argparse.Namespace, runtime_ids: list[str], targets: list[BackfillTarget]
) -> BackfillRun:
    normalized_runtime_ids = sorted(_dedupe(runtime_ids))
    if len(normalized_runtime_ids) > args.max_targets:
        raise ValueError(
            f"requested {len(normalized_runtime_ids)} runtimes; max_targets is {args.max_targets}"
        )
    if args.mode != "plan":
        blocked = [
            target.runtime_id
            for target in targets
            if target.state not in EXECUTABLE_TARGET_STATES
        ]
        if blocked:
            raise ValueError(
                f"requested backfill contains non-executable runtime(s): {', '.join(blocked)}"
            )

    policy = _policy(args)
    source_groups = _source_groups(targets)
    hash_payload: dict[str, Any] = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "control_plane_ref": _control_plane_ref(args.control_plane_ref),
        "stack_file": args.stack_file.as_posix(),
        "stack_name": _stack_name(args.stack_file),
        "stack_config_sha256": file_sha256(args.stack_file),
        "requested_runtime_ids": normalized_runtime_ids,
        "policy": asdict(policy),
        "targets": [asdict(target) for target in targets],
        "source_groups": [asdict(group) for group in source_groups],
    }
    return BackfillRun(
        schema_version=PLAN_SCHEMA_VERSION,
        control_plane_ref=hash_payload["control_plane_ref"],
        stack_file=hash_payload["stack_file"],
        stack_name=hash_payload["stack_name"],
        stack_config_sha256=hash_payload["stack_config_sha256"],
        mode=args.mode,
        requested_runtime_ids=normalized_runtime_ids,
        policy=policy,
        targets=targets,
        source_groups=source_groups,
        plan_hash=compute_plan_hash(hash_payload),
    )


def _verify_command(run: BackfillRun, source_id: str, runtime_id: str) -> list[str]:
    policy = run.policy
    command = [
        "uv",
        "run",
        "python",
        "scripts/verify_source_runtime_ecs.py",
        "--stack-file",
        run.stack_file,
        "--source-id",
        source_id,
        "--runtime-id",
        runtime_id,
        "--target-concurrency",
        "1",
        "--succeed-after-graph-ingest",
        "--run-page-limit",
        str(policy.run_page_limit),
        "--run-graph-page-limit",
        str(policy.run_graph_page_limit),
        "--run-event-limit",
        str(policy.run_event_limit),
        "--wait-timeout-seconds",
        str(policy.wait_timeout_seconds),
        "--run-attempt-timeout-seconds",
        str(policy.run_attempt_timeout_seconds),
    ]
    if run.mode == "run":
        command.append("--run")
    elif run.mode == "dry-run":
        command.append("--dry-run")
    if policy.stop_running_before_run:
        command.append("--stop-running-before-run")
    return command


def _write_tsv(targets: list[BackfillTarget]) -> None:
    print(
        "runtime_id\tsource_id\tfamily\tschedule_name\tschedule_expression\tstate\treason"
    )
    for target in targets:
        print("\t".join(str(value) for value in asdict(target).values()))


def _write_commands(run: BackfillRun) -> None:
    for group in run.source_groups:
        for runtime_id in group.runtime_ids:
            print(json.dumps(_verify_command(run, group.source_id, runtime_id)))


def _load_runtime_ids(args: argparse.Namespace) -> list[str]:
    values = list(args.runtime_id or [])
    if args.runtime_id_file:
        if str(args.runtime_id_file) == "-":
            values.extend(_runtime_ids_from_text(sys.stdin.read()))
        else:
            values.extend(
                _runtime_ids_from_text(args.runtime_id_file.read_text(encoding="utf-8"))
            )
    if args.diagnostics_file:
        values.extend(
            _missing_runtime_ids_from_diagnostics(
                args.diagnostics_file.read_text(encoding="utf-8", errors="replace")
            )
        )
    return sorted(_dedupe(values))


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create an approval-bound source-runtime backfill plan."
    )
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--runtime-id", action="append", default=[])
    parser.add_argument("--runtime-id-file", type=Path)
    parser.add_argument("--diagnostics-file", type=Path)
    parser.add_argument("--source-id", default="")
    parser.add_argument("--mode", choices=["plan", "dry-run", "run"], default="plan")
    parser.add_argument(
        "--format",
        choices=["tsv", "json", "commands", "run-json", "matrix-json"],
        default="tsv",
    )
    parser.add_argument("--control-plane-ref", default="")
    parser.add_argument("--max-targets", type=_positive_int, default=20)
    parser.add_argument("--max-targets-per-source", type=_positive_int, default=5)
    parser.add_argument("--source-parallelism", type=_positive_int, default=2)
    parser.add_argument("--source-cooldown-seconds", type=_non_negative_int, default=60)
    parser.add_argument("--max-attempts", type=_positive_int, default=2)
    parser.add_argument("--retry-backoff-seconds", type=_non_negative_int, default=60)
    parser.add_argument("--run-page-limit", type=_positive_int, default=25)
    parser.add_argument("--run-graph-page-limit", type=_positive_int, default=25)
    parser.add_argument("--run-event-limit", type=_positive_int, default=250)
    parser.add_argument("--wait-timeout-seconds", type=_positive_int, default=1800)
    parser.add_argument(
        "--run-attempt-timeout-seconds", type=_positive_int, default=900
    )
    parser.add_argument("--stop-running-before-run", action="store_true")
    args = parser.parse_args(argv)

    runtime_ids = _load_runtime_ids(args)
    if not runtime_ids and args.mode != "plan":
        raise SystemExit("no runtime ids were selected")
    if len(runtime_ids) > args.max_targets:
        raise SystemExit(
            f"requested {len(runtime_ids)} runtimes; max_targets is {args.max_targets}"
        )
    config = load_cerebro_config(args.stack_file)
    targets = plan_backfill(config, runtime_ids, args.source_id)
    run = backfill_run(args, runtime_ids, targets)
    validate_plan(asdict(run))

    if args.format == "json":
        print(
            json.dumps([asdict(target) for target in targets], indent=2, sort_keys=True)
        )
    elif args.format == "commands":
        _write_commands(run)
    elif args.format == "run-json":
        print(json.dumps(asdict(run), indent=2, sort_keys=True))
    elif args.format == "matrix-json":
        print(
            json.dumps(
                {"include": [asdict(group) for group in run.source_groups]},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    else:
        _write_tsv(targets)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
