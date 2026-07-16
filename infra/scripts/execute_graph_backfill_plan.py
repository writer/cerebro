#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any, Callable

try:
    from scripts.graph_backfill_contract import (
        BackfillPlanError,
        STATE_SCHEMA_VERSION,
        source_group,
        validate_execution_context,
        validate_plan,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from scripts.graph_backfill_contract import (
        BackfillPlanError,
        STATE_SCHEMA_VERSION,
        source_group,
        validate_execution_context,
        validate_plan,
    )


RunCommand = Callable[..., subprocess.CompletedProcess[str]]
Sleep = Callable[[float], None]
Clock = Callable[[], datetime]


@dataclass(frozen=True)
class FailureDecision:
    failure_class: str
    retryable: bool
    blocks_source: bool


def _load_json(path: Path, label: str) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise BackfillPlanError(f"{label} must be a JSON object")
    return loaded


def _failure_decision(output: str) -> FailureDecision:
    normalized = output.lower()
    if any(
        marker in normalized
        for marker in (
            "invalid token",
            "invalid_token",
            "http 401",
            "status code 401",
            "status=401",
            "unauthorized",
            "authentication failed",
            "invalid credentials",
            "credential expired",
            "token expired",
        )
    ):
        return FailureDecision("authentication", False, True)
    if any(
        marker in normalized
        for marker in (
            "http 403",
            "status code 403",
            "status=403",
            "accessdenied",
            "access denied",
            "permission denied",
            "forbidden",
        )
    ):
        return FailureDecision("authorization", False, True)
    if any(
        marker in normalized
        for marker in (
            "required aws secret imports are missing",
            "aws secret import preflight failed",
        )
    ):
        return FailureDecision("source_configuration", False, True)
    if any(
        marker in normalized
        for marker in (
            "http 429",
            "status code 429",
            "status=429",
            "rate limit",
            "too many requests",
            "throttl",
        )
    ):
        return FailureDecision("rate_limited", True, True)
    if any(
        marker in normalized
        for marker in (
            "timed out",
            "timeout",
            "temporarily unavailable",
            "connection reset",
            "service unavailable",
            "lease_not_acquired",
            "lease contention",
        )
    ):
        return FailureDecision("transient", True, False)
    if any(
        marker in normalized
        for marker in (
            "must have exactly one orchestrator schedule",
            "no deployed source runtime targets",
            "missing_target",
        )
    ):
        return FailureDecision("target_configuration", False, False)
    return FailureDecision("runtime_failure", True, False)


def _verifier_command(
    plan: dict[str, Any], source_id: str, runtime_id: str
) -> list[str]:
    policy = plan["policy"]
    command = [
        "uv",
        "run",
        "python",
        "scripts/verify_source_runtime_ecs.py",
        "--stack-file",
        plan["stack_file"],
        "--source-id",
        source_id,
        "--runtime-id",
        runtime_id,
        "--target-concurrency",
        "1",
        "--succeed-after-graph-ingest",
        "--run-page-limit",
        str(policy["run_page_limit"]),
        "--run-graph-page-limit",
        str(policy["run_graph_page_limit"]),
        "--run-event-limit",
        str(policy["run_event_limit"]),
        "--wait-timeout-seconds",
        str(policy["wait_timeout_seconds"]),
        "--run-attempt-timeout-seconds",
        str(policy["run_attempt_timeout_seconds"]),
    ]
    if plan["mode"] == "run":
        command.append("--run")
    elif plan["mode"] == "dry-run":
        command.append("--dry-run")
    if policy["stop_running_before_run"]:
        command.append("--stop-running-before-run")
    return command


def _timestamp(clock: Clock) -> str:
    return clock().astimezone(UTC).isoformat().replace("+00:00", "Z")


def _write_state(path: Path, state: dict[str, Any], clock: Clock) -> None:
    state["updated_at"] = _timestamp(clock)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def _load_resume_state(
    path: Path, plan: dict[str, Any], source_id: str
) -> dict[str, Any]:
    state = _load_json(path, "backfill resume state")
    if state.get("schema_version") != STATE_SCHEMA_VERSION:
        raise BackfillPlanError(
            "backfill resume state has an unsupported schema_version"
        )
    if state.get("plan_hash") != plan["plan_hash"]:
        raise BackfillPlanError("backfill resume state belongs to a different plan")
    if state.get("mode") != plan["mode"]:
        raise BackfillPlanError(
            "backfill resume state belongs to a different execution mode"
        )
    if state.get("source_id") != source_id:
        raise BackfillPlanError("backfill resume state belongs to a different source")
    targets = state.get("targets")
    if not isinstance(targets, list):
        raise BackfillPlanError("backfill resume state targets must be an array")
    expected_runtime_ids = source_group(plan, source_id)["runtime_ids"]
    actual_runtime_ids = [
        str(target.get("runtime_id") or "")
        for target in targets
        if isinstance(target, dict)
    ]
    if sorted(actual_runtime_ids) != expected_runtime_ids or len(
        actual_runtime_ids
    ) != len(set(actual_runtime_ids)):
        raise BackfillPlanError(
            "backfill resume state targets do not match the approved source lane"
        )
    return state


def _new_target_state(
    runtime_id: str, previous: dict[str, Any] | None
) -> dict[str, Any]:
    if previous and previous.get("status") == "completed":
        return {
            "runtime_id": runtime_id,
            "status": "completed",
            "attempts": int(previous.get("attempts") or 0),
            "failure_class": "",
            "resumed": True,
            "started_at": previous.get("started_at"),
            "completed_at": previous.get("completed_at"),
        }
    return {
        "runtime_id": runtime_id,
        "status": "pending",
        "attempts": int((previous or {}).get("attempts") or 0),
        "failure_class": "",
        "resumed": bool(previous),
        "started_at": None,
        "completed_at": None,
    }


def _print_process_output(result: subprocess.CompletedProcess[str]) -> None:
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr:
        print(
            result.stderr,
            file=sys.stderr,
            end="" if result.stderr.endswith("\n") else "\n",
        )


def _run_streaming(
    command: list[str], working_directory: Path
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        cwd=working_directory,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
    )
    captured: dict[str, list[str]] = {"stdout": [], "stderr": []}

    def pump(name: str, stream: Any, destination: Any) -> None:
        if stream is None:
            return
        for line in iter(stream.readline, ""):
            print(line, file=destination, end="", flush=True)
            captured[name].append(line)
            if len(captured[name]) > 200:
                del captured[name][0]
        stream.close()

    threads = [
        threading.Thread(
            target=pump, args=("stdout", process.stdout, sys.stdout), daemon=True
        ),
        threading.Thread(
            target=pump, args=("stderr", process.stderr, sys.stderr), daemon=True
        ),
    ]
    for thread in threads:
        thread.start()
    return_code = process.wait()
    for thread in threads:
        thread.join()
    return subprocess.CompletedProcess(
        command,
        return_code,
        "".join(captured["stdout"]),
        "".join(captured["stderr"]),
    )


def execute_plan(
    plan: dict[str, Any],
    expected_plan_hash: str,
    source_id: str,
    state_path: Path,
    *,
    resume_state_path: Path | None = None,
    working_directory: Path | None = None,
    verify_context: bool = True,
    run_command: RunCommand | None = None,
    sleep: Sleep = time.sleep,
    clock: Clock = lambda: datetime.now(UTC),
) -> int:
    if not expected_plan_hash.strip():
        raise BackfillPlanError(
            "expected plan hash is required for dry-run and run modes"
        )
    validate_plan(plan, expected_plan_hash)
    if plan["mode"] == "plan":
        raise BackfillPlanError("plan mode cannot be executed")
    execution_directory = working_directory or Path.cwd()
    if verify_context:
        validate_execution_context(plan, execution_directory)

    group = source_group(plan, source_id)
    runtime_ids = group["runtime_ids"]
    previous_by_runtime: dict[str, dict[str, Any]] = {}
    if resume_state_path is not None:
        previous = _load_resume_state(resume_state_path, plan, source_id)
        previous_by_runtime = {
            str(target.get("runtime_id") or ""): target
            for target in previous["targets"]
            if isinstance(target, dict)
        }

    started_at = _timestamp(clock)
    state: dict[str, Any] = {
        "schema_version": STATE_SCHEMA_VERSION,
        "plan_hash": plan["plan_hash"],
        "control_plane_ref": plan["control_plane_ref"],
        "stack_name": plan["stack_name"],
        "mode": plan["mode"],
        "source_id": source_id,
        "source_key": group["source_key"],
        "execution_ref": os.environ.get("GITHUB_RUN_ID", "local"),
        "execution_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        "status": "running",
        "started_at": started_at,
        "completed_at": None,
        "targets": [
            _new_target_state(runtime_id, previous_by_runtime.get(runtime_id))
            for runtime_id in runtime_ids
        ],
    }
    _write_state(state_path, state, clock)

    policy = plan["policy"]
    source_block: FailureDecision | None = None
    for index, target_state in enumerate(state["targets"]):
        runtime_id = target_state["runtime_id"]
        if target_state["status"] == "completed":
            print(
                json.dumps(
                    {
                        "event": "backfill_target_resumed",
                        "runtime_id": runtime_id,
                        "source_id": source_id,
                    },
                    sort_keys=True,
                )
            )
            continue
        if source_block is not None:
            target_state.update(
                {
                    "status": "blocked",
                    "failure_class": source_block.failure_class,
                    "completed_at": _timestamp(clock),
                }
            )
            _write_state(state_path, state, clock)
            continue

        target_state["status"] = "running"
        target_state["started_at"] = _timestamp(clock)
        _write_state(state_path, state, clock)
        command = _verifier_command(plan, source_id, runtime_id)
        for attempt in range(1, policy["max_attempts"] + 1):
            target_state["attempts"] += 1
            print(
                json.dumps(
                    {
                        "attempt": attempt,
                        "event": "backfill_target_attempt",
                        "runtime_id": runtime_id,
                        "source_id": source_id,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            try:
                if run_command is None:
                    result = _run_streaming(command, execution_directory)
                else:
                    result = run_command(
                        command,
                        check=False,
                        text=True,
                        capture_output=True,
                        cwd=execution_directory,
                    )
            except OSError as exc:
                result = subprocess.CompletedProcess(
                    command,
                    1,
                    "",
                    f"transient command start failure: {type(exc).__name__}",
                )
            if run_command is not None:
                _print_process_output(result)
            if result.returncode == 0:
                target_state.update(
                    {
                        "status": "completed",
                        "failure_class": "",
                        "completed_at": _timestamp(clock),
                    }
                )
                _write_state(state_path, state, clock)
                break

            decision = _failure_decision(
                f"{result.stdout or ''}\n{result.stderr or ''}"
            )
            target_state["failure_class"] = decision.failure_class
            if decision.retryable and attempt < policy["max_attempts"]:
                target_state["status"] = "retry_wait"
                _write_state(state_path, state, clock)
                delay = policy["retry_backoff_seconds"] * (2 ** (attempt - 1))
                print(
                    json.dumps(
                        {
                            "delay_seconds": delay,
                            "event": "backfill_target_retry",
                            "failure_class": decision.failure_class,
                            "runtime_id": runtime_id,
                            "source_id": source_id,
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
                sleep(delay)
                target_state["status"] = "running"
                _write_state(state_path, state, clock)
                continue

            target_state.update(
                {
                    "status": "failed",
                    "completed_at": _timestamp(clock),
                }
            )
            _write_state(state_path, state, clock)
            if decision.blocks_source:
                source_block = decision
            break

        remaining_pending = any(
            item["status"] not in {"completed", "failed", "blocked"}
            for item in state["targets"][index + 1 :]
        )
        if (
            plan["mode"] == "run"
            and target_state["status"] == "completed"
            and remaining_pending
            and policy["source_cooldown_seconds"] > 0
        ):
            print(
                json.dumps(
                    {
                        "delay_seconds": policy["source_cooldown_seconds"],
                        "event": "backfill_source_cooldown",
                        "source_id": source_id,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            sleep(policy["source_cooldown_seconds"])

    statuses = {target["status"] for target in state["targets"]}
    state["status"] = "completed" if statuses == {"completed"} else "failed"
    state["completed_at"] = _timestamp(clock)
    _write_state(state_path, state, clock)
    return 0 if state["status"] == "completed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute one source lane from an approval-bound backfill plan."
    )
    parser.add_argument("plan_file", type=Path)
    parser.add_argument("--expected-plan-hash", required=True)
    parser.add_argument("--source-id")
    parser.add_argument("--state-output", type=Path)
    parser.add_argument("--resume-state", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    plan = _load_json(args.plan_file, "backfill plan")
    if args.validate_only:
        validate_plan(plan, args.expected_plan_hash)
        if plan["mode"] == "plan":
            raise BackfillPlanError("plan mode cannot be executed")
        validate_execution_context(plan, Path.cwd())
        return 0
    if not args.source_id or args.state_output is None:
        parser.error(
            "--source-id and --state-output are required unless --validate-only is used"
        )
    return execute_plan(
        plan,
        args.expected_plan_hash,
        args.source_id,
        args.state_output,
        resume_state_path=args.resume_state,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BackfillPlanError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
