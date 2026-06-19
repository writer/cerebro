#!/usr/bin/env python3
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any

try:
    from aws import source_runtime_scope
except ModuleNotFoundError:  # pragma: no cover - used when executed as scripts/verify_source_runtime_ecs.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from aws import source_runtime_scope

try:
    from scripts import verify_aws_secret_imports as secret_imports
except ImportError:  # pragma: no cover - used when executed as scripts/verify_source_runtime_ecs.py
    import verify_aws_secret_imports as secret_imports


EXPECTED_STACK_ACCOUNTS = {
    "sec-dev": "944130631940",
    "go-prod": "837279440628",
}

SENSITIVE_TEXT_PATTERNS = (
    (re.compile(r"arn:aws[a-zA-Z-]*:[^\s,;)\]}]+"), "[redacted-arn]"),
    (re.compile(r"\btask/[A-Za-z0-9_.:/-]+"), "[redacted-task]"),
    (re.compile(r"\b((?:cerebro|source-runtime-bootstrap)/)[A-Za-z0-9_.-]+"), r"\1[redacted-task]"),
    (re.compile(r"\b\d{12}\b"), "[redacted-account]"),
    (re.compile(r"https?://([A-Za-z0-9-]+\.)+[A-Za-z]{2,}(:\d+)?(/[^\s,;)\]}]*)?"), "[redacted-url]"),
    (re.compile(r"\b([A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"), "[redacted-host]"),
    (re.compile(r"(?i)(RequestID:\s*)([A-Za-z0-9-]+)"), r"\1[redacted-request-id]"),
    (re.compile(r"(?i)(request_id[\"'=:\s]+)([A-Za-z0-9_.-]+)"), r"\1[redacted-request-id]"),
    (re.compile(r"(?i)(secret[\"'=:\s]+)([A-Za-z0-9_./:=@+-]+)"), r"\1[redacted-secret]"),
    (re.compile(r"(?i)(token[\"'=:\s]+)([A-Za-z0-9_./:=@+-]+)"), r"\1[redacted-token]"),
    (re.compile(r"(?i)(secret\s+)([A-Za-z0-9_./:=@+-]+)"), r"\1[redacted-secret]"),
    (re.compile(r"(?i)(token\s+)([A-Za-z0-9_./:=@+-]+)"), r"\1[redacted-token]"),
)

FAIL_CLOSED_CONTRACT_PROBE_STATUSES = {"failure", "failed", "stale", "unknown", "not_configured", "missing"}
FAIL_CLOSED_LINK_STATUSES = {"orphan", "missing_resource", "missing_case"}
BOOTSTRAP_CONTAINER_NAME = "source-runtime-bootstrap"
BOOTSTRAP_ENV_NAME = "CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON"


def _sanitize_text(value: Any) -> str:
    text = str(value)
    for pattern, replacement in SENSITIVE_TEXT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _task_ref(task_arn: str) -> str:
    return "task/[redacted-task]"


@dataclass(frozen=True)
class RuntimeTarget:
    runtime_id: str
    schedule_name: str
    rule_name: str
    target: dict[str, Any]


@dataclass(frozen=True)
class SecretImportPreflightFinding:
    env_name: str
    key_path: str
    category: str
    reason: str


@dataclass(frozen=True)
class VerificationResult:
    runtime_id: str
    task_arn: str
    exit_code: int | None
    runtime_status: str
    sync_status: str
    graph_ingest_status: str
    events_appended: int | None
    pages_read: int | None
    entities_projected: int | None = None
    links_projected: int | None = None


@dataclass(frozen=True)
class TaskLogOptions:
    log_group: str
    stream_prefix: str


@dataclass(frozen=True)
class VerificationOptions:
    run: bool = False
    wait_timeout_seconds: int = 3600
    poll_seconds: int = 10
    region: str = "us-east-1"
    run_page_limit: int | None = None
    run_graph_page_limit: int | None = None
    run_event_limit: int | None = None
    allow_lease_contention_skip: bool = False
    stop_running_before_run: bool = False
    stop_timeout_seconds: int = 180
    failed_run_retry_seconds: int = 0
    run_attempt_timeout_seconds: int = 0
    succeed_after_graph_ingest: bool = False
    max_age_minutes: int = 180
    bootstrap_runtime_ids: tuple[str, ...] = ()


class RuntimeSkippedError(RuntimeError):
    def __init__(self, runtime_id: str, task_arn: str, reason: str) -> None:
        self.runtime_id = runtime_id
        self.task_arn = task_arn
        self.reason = reason
        detail = f" ({reason})" if reason else ""
        super().__init__(f"{runtime_id} orchestrator runtime status is skipped{detail}: {_task_ref(task_arn)}")


class RuntimeTaskFailedError(RuntimeError):
    def __init__(self, runtime_id: str, task_arn: str, exit_code: int | None, log_summary: str) -> None:
        self.runtime_id = runtime_id
        self.task_arn = task_arn
        self.exit_code = exit_code
        detail = f"\nRecent task logs:\n{_sanitize_text(log_summary)}" if log_summary else ""
        super().__init__(f"{runtime_id} task exited with {exit_code}: {_task_ref(task_arn)}{detail}")


class RuntimeVerificationFailedError(RuntimeError):
    def __init__(self, runtime_id: str, task_arn: str, phase: str, status: str, diagnostics: str = "") -> None:
        self.runtime_id = runtime_id
        self.task_arn = task_arn
        self.phase = phase
        self.status = status
        detail = f"\n{_sanitize_text(diagnostics)}" if diagnostics else ""
        super().__init__(f"{runtime_id} {phase} status is {status}: {_task_ref(task_arn)}{detail}")


def _stack_name(path: Path) -> str:
    name = path.name
    if name.startswith("Pulumi.") and name.endswith(".yaml"):
        return name.removeprefix("Pulumi.").removesuffix(".yaml")
    return path.stem


def _load_config(path: Path) -> dict[str, Any]:
    return source_runtime_scope.load_cerebro_config(path)


def _runtime_id_from_command(command: Any) -> str:
    return source_runtime_scope.runtime_id_from_command(command)


def _container_override_command(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    overrides = value.get("containerOverrides") or []
    if not isinstance(overrides, list):
        return []
    for override in overrides:
        if not isinstance(override, dict) or override.get("name") != "cerebro":
            continue
        command = override.get("command")
        if isinstance(command, list):
            return [str(part) for part in command]
    return []


def _container_override_bootstrap_payload(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    overrides = value.get("containerOverrides") or []
    if not isinstance(overrides, list):
        return ""
    for override in overrides:
        if not isinstance(override, dict) or override.get("name") != BOOTSTRAP_CONTAINER_NAME:
            continue
        for item in override.get("environment") or []:
            if item.get("name") == BOOTSTRAP_ENV_NAME:
                return str(item.get("value") or "")
    return ""


def _target_command(target: RuntimeTarget) -> list[str]:
    raw_input = target.target.get("Input")
    if not raw_input:
        return []
    try:
        return _container_override_command(json.loads(str(raw_input)))
    except json.JSONDecodeError:
        return []


def _target_bootstrap_payload(target: RuntimeTarget) -> str:
    raw_input = target.target.get("Input")
    if not raw_input:
        return ""
    try:
        return _container_override_bootstrap_payload(json.loads(str(raw_input)))
    except json.JSONDecodeError:
        return ""


def _task_command(task: dict[str, Any]) -> list[str]:
    return _container_override_command(task.get("overrides") or {})


def _task_matches_target(task: dict[str, Any], target: RuntimeTarget) -> bool:
    runtime_id = _runtime_id_from_command(_task_command(task))
    if runtime_id:
        return runtime_id == target.runtime_id
    if _target_command(target):
        return False
    return _task_family(str(task.get("taskDefinitionArn") or "")) == _task_family(target.target["EcsParameters"]["TaskDefinitionArn"])


def _schedule_suffix(value: str) -> str:
    chars = []
    for char in str(value).strip().lower():
        if ("a" <= char <= "z") or ("0" <= char <= "9"):
            chars.append(char)
        elif chars and chars[-1] != "-":
            chars.append("-")
    suffix = "".join(chars).strip("-")
    if not suffix:
        raise ValueError("orchestrator schedule name must include at least one alphanumeric character")
    return suffix


def _schedule_backend(schedule: dict[str, Any]) -> str:
    return str(schedule.get("backend") or schedule.get("scheduleBackend") or "eventbridge").strip()


def _schedule_state(schedule: dict[str, Any]) -> str:
    return str(schedule.get("state") or schedule.get("scheduleState") or "ENABLED").strip().upper()


def _aws(args: list[str], region: str) -> Any:
    command = ["aws", *args, "--region", region, "--output", "json"]
    try:
        completed = subprocess.run(command, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        detail = _sanitize_text((exc.stderr or exc.stdout or "").strip())
        message = f"{_sanitize_text(' '.join(command))} failed with exit code {exc.returncode}"
        if detail:
            message = f"{message}: {detail}"
        raise RuntimeError(message) from exc
    if not completed.stdout.strip():
        return None
    return json.loads(completed.stdout)


def _parse_aws_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=UTC)
    if isinstance(value, str):
        text = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _declared_runtime_ids(config: dict[str, Any], source_id: str, requested: set[str], families: set[str] | None = None) -> list[str]:
    return source_runtime_scope.declared_runtime_ids(config, source_id, requested, families)


def _observability_runtime_ids(
    config: dict[str, Any],
    source_id: str,
    requested: set[str],
    families: set[str] | None = None,
) -> list[str]:
    runtime_ids = source_runtime_scope.observability_runtime_ids(
        config,
        source_id,
        requested,
        families,
        enabled=True,
    )
    matching_disabled = source_runtime_scope.observability_runtime_ids(
        config,
        source_id,
        requested,
        families,
        enabled=False,
    )
    if matching_disabled:
        print(
            "INFO disabled observability runtimes skipped: " + ", ".join(sorted(matching_disabled)),
            file=sys.stderr,
        )
    return runtime_ids


def _disabled_observability_runtime_ids(
    config: dict[str, Any],
    source_id: str,
    requested: set[str],
    families: set[str] | None = None,
) -> list[str]:
    return source_runtime_scope.observability_runtime_ids(
        config,
        source_id,
        requested,
        families,
        enabled=False,
    )


def _runtime_targets(
    config: dict[str, Any],
    runtime_ids: list[str],
    resource_prefix: str,
    region: str,
    allow_missing_targets: bool = False,
) -> list[RuntimeTarget]:
    schedules = config.get("orchestratorSchedules") or []
    if not isinstance(schedules, list):
        schedules = []
    targets = []
    for runtime_id in runtime_ids:
        matches = [
            schedule
            for schedule in schedules
            if isinstance(schedule, dict) and _runtime_id_from_command(schedule.get("command")) == runtime_id
        ]
        if len(matches) != 1:
            raise ValueError(f"runtime {runtime_id!r} must have exactly one orchestrator schedule, found {len(matches)}")
        schedule = matches[0]
        if _schedule_state(schedule) == "DISABLED":
            print(f"warning: skipping {runtime_id}; declared orchestrator schedule is DISABLED")
            continue
        schedule_name = str(schedule.get("name") or runtime_id)
        suffix = _schedule_suffix(schedule_name)
        rule_name = f"{resource_prefix}-orchestrator" if suffix == "default" else f"{resource_prefix}-orchestrator-{suffix}"
        backend = _schedule_backend(schedule)
        if backend == "scheduler":
            group_name = f"{resource_prefix}-orchestrator"
            try:
                response = _aws(["scheduler", "get-schedule", "--group-name", group_name, "--name", rule_name], region)
            except RuntimeError as exc:
                if allow_missing_targets and "ResourceNotFoundException" in str(exc):
                    print(f"warning: skipping {runtime_id}; deployed EventBridge Scheduler schedule {group_name}/{rule_name!r} is missing")
                    continue
                raise
            target = response.get("Target") or {}
            if not target:
                if allow_missing_targets:
                    print(f"warning: skipping {runtime_id}; deployed EventBridge Scheduler schedule {group_name}/{rule_name!r} has no target yet")
                    continue
                raise ValueError(f"EventBridge Scheduler schedule {group_name}/{rule_name!r} must have a target")
            targets.append(RuntimeTarget(runtime_id=runtime_id, schedule_name=schedule_name, rule_name=rule_name, target=target))
            continue
        if backend != "eventbridge":
            raise ValueError(f"unsupported orchestrator schedule backend {backend!r}")
        try:
            response = _aws(["events", "list-targets-by-rule", "--rule", rule_name], region)
        except RuntimeError as exc:
            if allow_missing_targets and "ResourceNotFoundException" in str(exc):
                print(f"warning: skipping {runtime_id}; deployed EventBridge rule {rule_name!r} is missing")
                continue
            raise
        rule_targets = response.get("Targets") or []
        if len(rule_targets) != 1:
            if allow_missing_targets and not rule_targets:
                print(f"warning: skipping {runtime_id}; deployed EventBridge rule {rule_name!r} has no target yet")
                continue
            raise ValueError(f"EventBridge rule {rule_name!r} must have exactly one target, found {len(rule_targets)}")
        targets.append(RuntimeTarget(runtime_id=runtime_id, schedule_name=schedule_name, rule_name=rule_name, target=rule_targets[0]))
    return targets


def _task_family(task_definition_arn: str) -> str:
    return task_definition_arn.rsplit("/", 1)[-1].rsplit(":", 1)[0]


def _latest_active_task_definition(task_definition: str, region: str) -> str:
    response = _aws(["ecs", "describe-task-definition", "--task-definition", task_definition], region)
    definition = response.get("taskDefinition") or {}
    if definition.get("status") == "ACTIVE":
        return str(definition.get("taskDefinitionArn") or task_definition)
    family = str(definition.get("family") or _task_family(task_definition)).strip()
    if not family:
        raise RuntimeError(f"could not determine ECS task definition family for {task_definition}")
    active = _aws(
        [
            "ecs",
            "list-task-definitions",
            "--family-prefix",
            family,
            "--status",
            "ACTIVE",
            "--sort",
            "DESC",
            "--max-items",
            "1",
        ],
        region,
    )
    arns = active.get("taskDefinitionArns") or []
    if not arns:
        raise RuntimeError(f"no active ECS task definitions found for family {family}")
    replacement = str(arns[0])
    print(
        f"Using latest active ECS task definition for family {family} instead of inactive configured revision",
        file=sys.stderr,
    )
    return replacement


def _verification_command(
    runtime_id: str,
    page_limit: int | None,
    graph_page_limit: int | None,
    event_limit: int | None,
) -> list[str] | None:
    if page_limit is None and graph_page_limit is None and event_limit is None:
        return None
    command = ["orchestrator", "run", f"runtime_id={runtime_id}"]
    if page_limit is not None:
        command.append(f"page_limit={page_limit}")
    if graph_page_limit is not None:
        command.append(f"graph_page_limit={graph_page_limit}")
    if event_limit is not None:
        command.append(f"event_limit={event_limit}")
    return command


def _run_task(
    target: RuntimeTarget,
    region: str,
    command_override: list[str] | None = None,
    bootstrap_runtime_ids: tuple[str, ...] = (),
) -> str:
    ecs_params = target.target["EcsParameters"]
    network = ecs_params["NetworkConfiguration"]["awsvpcConfiguration"]
    subnets = ",".join(network["Subnets"])
    security_groups = ",".join(network["SecurityGroups"])
    assign_public_ip = network.get("AssignPublicIp", "DISABLED")
    task_definition = _latest_active_task_definition(ecs_params["TaskDefinitionArn"], region)
    args = [
        "ecs",
        "run-task",
        "--cluster",
        target.target["Arn"],
        "--task-definition",
        task_definition,
        "--launch-type",
        ecs_params.get("LaunchType", "FARGATE"),
        "--network-configuration",
        f"awsvpcConfiguration={{subnets=[{subnets}],securityGroups=[{security_groups}],assignPublicIp={assign_public_ip}}}",
    ]
    effective_command = command_override if command_override is not None else _target_command(target)
    container_overrides = []
    if effective_command:
        container_overrides.append({"name": "cerebro", "command": effective_command})
    if bootstrap_runtime_ids:
        requested_bootstrap_runtime_ids = set(bootstrap_runtime_ids)
        target_payload = _target_bootstrap_payload(target)
        scoped_payload = ""
        if target_payload and requested_bootstrap_runtime_ids.issubset(_bootstrap_payload_runtime_ids(target_payload)):
            scoped_payload = _scoped_bootstrap_payload(target_payload, requested_bootstrap_runtime_ids)
        if not scoped_payload:
            scoped_payload = _scoped_bootstrap_payload_from_task_definition(
                task_definition,
                requested_bootstrap_runtime_ids,
                region,
            )
        container_overrides.append(
            {
                "name": BOOTSTRAP_CONTAINER_NAME,
                "environmentFiles": [],
                "environment": [{"name": BOOTSTRAP_ENV_NAME, "value": scoped_payload}],
            }
        )
    if container_overrides:
        args.extend(["--overrides", json.dumps({"containerOverrides": container_overrides})])
    response = _aws(args, region)
    failures = response.get("failures") or []
    if failures:
        raise RuntimeError(f"failed to start {target.runtime_id}: {_sanitize_text(failures)}")
    tasks = response.get("tasks") or []
    if len(tasks) != 1:
        raise RuntimeError(f"expected one task for {target.runtime_id}, got {len(tasks)}")
    return tasks[0]["taskArn"]


def _running_task_arns(target: RuntimeTarget, region: str) -> list[str]:
    family = _task_family(target.target["EcsParameters"]["TaskDefinitionArn"])
    response = _aws(
        [
            "ecs",
            "list-tasks",
            "--cluster",
            target.target["Arn"],
            "--desired-status",
            "RUNNING",
            "--family",
            family,
            "--max-results",
            "100",
        ],
        region,
    )
    task_arns = [str(task_arn) for task_arn in response.get("taskArns") or []]
    if not task_arns:
        return []
    tasks = _describe_tasks(target.target["Arn"], task_arns, region)
    return [str(task["taskArn"]) for task in tasks if _task_matches_target(task, target)]


def _stop_running_tasks(
    target: RuntimeTarget,
    region: str,
    reason: str,
    timeout_seconds: int,
    poll_seconds: int,
) -> None:
    task_arns = _running_task_arns(target, region)
    if not task_arns:
        return
    for task_arn in task_arns:
        print(f"Stopping running {target.runtime_id} task before verification: {_task_ref(task_arn)}", file=sys.stderr)
        _aws(
            [
                "ecs",
                "stop-task",
                "--cluster",
                target.target["Arn"],
                "--task",
                task_arn,
                "--reason",
                reason,
            ],
            region,
        )
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        tasks = _describe_tasks(target.target["Arn"], task_arns, region)
        running = [task.get("taskArn") for task in tasks if task.get("lastStatus") != "STOPPED"]
        if not running:
            return
        time.sleep(poll_seconds)
    raise TimeoutError(f"{len(task_arns)} running {target.runtime_id} task(s) did not stop within {timeout_seconds} seconds")


def _stop_task(
    target: RuntimeTarget,
    task_arn: str,
    region: str,
    reason: str,
    timeout_seconds: int,
    poll_seconds: int,
) -> None:
    print(f"Stopping timed-out {target.runtime_id} verification task: {_task_ref(task_arn)}", file=sys.stderr)
    _aws(
        [
            "ecs",
            "stop-task",
            "--cluster",
            target.target["Arn"],
            "--task",
            task_arn,
            "--reason",
            reason,
        ],
        region,
    )
    _wait_for_task(target.target["Arn"], task_arn, timeout_seconds, poll_seconds, region)


def _latest_task(target: RuntimeTarget, max_age_minutes: int, region: str) -> str:
    family = _task_family(target.target["EcsParameters"]["TaskDefinitionArn"])
    response = _aws(
        [
            "ecs",
            "list-tasks",
            "--cluster",
            target.target["Arn"],
            "--desired-status",
            "STOPPED",
            "--family",
            family,
            "--max-results",
            "100",
        ],
        region,
    )
    task_arns = response.get("taskArns") or []
    if not task_arns:
        raise RuntimeError(f"no stopped tasks found for {target.runtime_id}")
    tasks = _describe_tasks(target.target["Arn"], task_arns, region)
    now = datetime.now(UTC)
    fresh_tasks = []
    for task in tasks:
        if not _task_matches_target(task, target):
            continue
        stopped_at = _parse_aws_datetime(task.get("stoppedAt")) or _parse_aws_datetime(task.get("createdAt"))
        if stopped_at is not None and now - stopped_at <= timedelta(minutes=max_age_minutes):
            fresh_tasks.append(task)
    if not fresh_tasks:
        raise RuntimeError(f"no stopped tasks for {target.runtime_id} within {max_age_minutes} minutes")
    fresh_tasks.sort(key=lambda task: _parse_aws_datetime(task.get("stoppedAt")) or datetime.min.replace(tzinfo=UTC), reverse=True)
    return fresh_tasks[0]["taskArn"]


def _describe_tasks(cluster_arn: str, task_arns: list[str], region: str) -> list[dict[str, Any]]:
    response = _aws(["ecs", "describe-tasks", "--cluster", cluster_arn, "--tasks", *task_arns], region)
    failures = response.get("failures") or []
    if failures:
        raise RuntimeError(f"failed to describe ECS tasks: {failures}")
    return response.get("tasks") or []


def _task_stop_summary(task: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("stopCode", "stoppedReason"):
        value = str(task.get(key) or "").strip()
        if value:
            parts.append(f"{key}={value}")
    for container in task.get("containers") or []:
        name = str(container.get("name") or "container")
        fields = []
        for key in ("lastStatus", "exitCode", "reason"):
            value = container.get(key)
            if value not in (None, ""):
                fields.append(f"{key}={value}")
        if fields:
            parts.append(f"{name}({', '.join(fields)})")
    if not parts:
        return "no ECS stop reason available"
    return _sanitize_text("; ".join(parts))[:2000]


def _wait_for_task(cluster_arn: str, task_arn: str, timeout_seconds: int, poll_seconds: int, region: str) -> None:
    task_id = "[redacted-task]"
    started = time.time()
    deadline = time.time() + timeout_seconds
    next_progress = 0.0
    while time.time() < deadline:
        tasks = _describe_tasks(cluster_arn, [task_arn], region)
        status = str(tasks[0].get("lastStatus") or "UNKNOWN") if tasks else "UNKNOWN"
        if status == "STOPPED":
            if tasks:
                print(f"INFO source runtime task={task_id} stopped: {_task_stop_summary(tasks[0])}", file=sys.stderr)
            return
        now = time.time()
        if now >= next_progress:
            elapsed = int(now - started)
            width = 20
            progress = min(1.0, elapsed / max(1, timeout_seconds))
            filled = int(progress * width)
            bar = "#" * filled + "-" * (width - filled)
            print(
                f"WAIT source runtime task={task_id} status={status} [{bar}] {elapsed}s/{timeout_seconds}s",
                file=sys.stderr,
                flush=True,
            )
            next_progress = now + max(30, poll_seconds)
        time.sleep(poll_seconds)
    raise TimeoutError(f"task {_task_ref(task_arn)} did not stop within {timeout_seconds} seconds")


def _task_id(task_arn: str) -> str:
    return task_arn.rsplit("/", 1)[-1]


def _container_log_options(
    task_definition: str,
    container_name: str,
    region: str,
    cache: dict[tuple[str, str], TaskLogOptions] | None = None,
) -> TaskLogOptions:
    cache_key = (task_definition, container_name)
    if cache is not None and cache_key in cache:
        return cache[cache_key]
    response = _aws(["ecs", "describe-task-definition", "--task-definition", task_definition], region)
    container_definitions = response["taskDefinition"]["containerDefinitions"]
    container = next(container for container in container_definitions if container.get("name") == container_name)
    options = container["logConfiguration"]["options"]
    result = TaskLogOptions(options["awslogs-group"], options["awslogs-stream-prefix"])
    if cache is not None:
        cache[cache_key] = result
    return result


def _task_log_options(
    task_definition: str,
    region: str,
    cache: dict[tuple[str, str], TaskLogOptions] | None = None,
) -> TaskLogOptions:
    return _container_log_options(task_definition, "cerebro", region, cache)


def _task_logs(
    task: dict[str, Any],
    region: str,
    log_options_cache: dict[tuple[str, str], TaskLogOptions] | None = None,
    container_name: str = "cerebro",
) -> list[dict[str, Any]]:
    raw_messages = _raw_task_log_messages(task, region, log_options_cache, container_name)
    messages = []
    for raw_message in raw_messages:
        try:
            messages.append(json.loads(raw_message or "{}"))
        except json.JSONDecodeError:
            continue
    return messages


def _raw_task_log_messages(
    task: dict[str, Any],
    region: str,
    log_options_cache: dict[tuple[str, str], TaskLogOptions] | None = None,
    container_name: str = "cerebro",
) -> list[str]:
    task_definition = task["taskDefinitionArn"]
    options = _container_log_options(task_definition, container_name, region, log_options_cache)
    stream = f"{options.stream_prefix}/{container_name}/{_task_id(task['taskArn'])}"
    events = _aws(
        [
            "logs",
            "get-log-events",
            "--log-group-name",
            options.log_group,
            "--log-stream-name",
            stream,
            "--limit",
            "400",
        ],
        region,
    )
    return [str(event.get("message") or "") for event in events.get("events") or []]


def _summarize_log_messages(messages: list[dict[str, Any]], limit: int = 20) -> str:
    keys = (
        "level",
        "msg",
        "message",
        "error",
        "kind",
        "name",
        "status",
        "reason",
        "events_appended",
        "pages_read",
        "entities_projected",
        "links_projected",
    )
    lines = []
    for message in messages[-limit:]:
        summary = {key: message[key] for key in keys if key in message}
        if summary:
            line = _sanitize_text(json.dumps(summary, sort_keys=True))
        else:
            line = _sanitize_text(json.dumps(message, sort_keys=True))
        lines.append(line[:2000])
    return "\n".join(lines)


def _summarize_raw_log_messages(messages: list[str], limit: int = 20) -> str:
    lines = []
    for message in messages[-limit:]:
        line = _sanitize_text(message.strip())
        if line:
            lines.append(line[:2000])
    return "\n".join(lines)


def _s3_bucket_key_from_arn(value: str) -> tuple[str, str]:
    prefix = "arn:aws:s3:::"
    if not value.startswith(prefix):
        raise ValueError("environment file must be an S3 object ARN")
    bucket_key = value.removeprefix(prefix)
    if "/" not in bucket_key:
        raise ValueError("environment file ARN must include an object key")
    bucket, key = bucket_key.split("/", 1)
    if not bucket or not key:
        raise ValueError("environment file ARN must include a bucket and key")
    return bucket, key


def _read_s3_object(bucket: str, key: str, region: str) -> str:
    completed = subprocess.run(
        ["aws", "s3", "cp", f"s3://{bucket}/{key}", "-", "--region", region],
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout


def _env_file_value(content: str, name: str) -> str:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == name:
            return value
    return ""


def _bootstrap_payload_from_task_definition(task_definition: dict[str, Any], region: str | None = None) -> str:
    for container in task_definition.get("containerDefinitions") or []:
        if container.get("name") != BOOTSTRAP_CONTAINER_NAME:
            continue
        for item in container.get("environment") or []:
            if item.get("name") == BOOTSTRAP_ENV_NAME:
                return str(item.get("value") or "")
        if not region:
            continue
        for environment_file in container.get("environmentFiles") or []:
            if str(environment_file.get("type") or "").lower() != "s3":
                continue
            value = str(environment_file.get("value") or "")
            if not value:
                continue
            bucket, key = _s3_bucket_key_from_arn(value)
            payload = _env_file_value(_read_s3_object(bucket, key, region), BOOTSTRAP_ENV_NAME)
            if payload:
                return payload
    return ""


def _bootstrap_payload_runtime_ids(payload: str) -> set[str]:
    if not payload:
        return set()
    parsed = json.loads(payload)
    runtimes = parsed.get("runtimes") if isinstance(parsed, dict) else parsed
    if not isinstance(runtimes, list):
        raise ValueError("bootstrap payload must contain a runtimes list")
    runtime_ids: set[str] = set()
    for runtime in runtimes:
        if not isinstance(runtime, dict):
            continue
        runtime_id = str(runtime.get("id") or "").strip()
        if runtime_id:
            runtime_ids.add(runtime_id)
    return runtime_ids


def _scoped_bootstrap_payload(payload: str, runtime_ids: set[str]) -> str:
    if not runtime_ids:
        return payload
    parsed = json.loads(payload)
    runtimes = parsed.get("runtimes") if isinstance(parsed, dict) else parsed
    if not isinstance(runtimes, list):
        raise ValueError("bootstrap payload must contain a runtimes list")
    scoped = [
        runtime
        for runtime in runtimes
        if isinstance(runtime, dict) and str(runtime.get("id") or "").strip() in runtime_ids
    ]
    present = {str(runtime.get("id") or "").strip() for runtime in scoped if isinstance(runtime, dict)}
    missing = sorted(runtime_ids - present)
    if missing:
        raise ValueError(f"bootstrap payload missing requested runtime IDs: {','.join(missing)}")
    return json.dumps({"runtimes": scoped}, sort_keys=True, separators=(",", ":"))


def _scoped_bootstrap_payload_from_task_definition(
    task_definition_arn: str,
    runtime_ids: set[str],
    region: str,
) -> str:
    if not runtime_ids:
        return ""
    response = _aws(["ecs", "describe-task-definition", "--task-definition", task_definition_arn], region)
    payload = _bootstrap_payload_from_task_definition(response.get("taskDefinition") or {}, region)
    if not payload:
        raise ValueError("bootstrap payload is missing from task definition")
    return _scoped_bootstrap_payload(payload, runtime_ids)


def _bootstrap_payload_diagnostics(
    runtime_id: str,
    task_definition: dict[str, Any],
    requested_runtime_ids: set[str],
    region: str | None = None,
) -> tuple[set[str], str]:
    payload = _bootstrap_payload_from_task_definition(task_definition, region)
    return _bootstrap_payload_diagnostics_from_payload(runtime_id, payload, requested_runtime_ids)


def _bootstrap_payload_diagnostics_from_payload(
    runtime_id: str,
    payload: str,
    requested_runtime_ids: set[str],
) -> tuple[set[str], str]:
    if not payload:
        return set(), (
            "bootstrap diagnostics: task definition is missing "
            f"{BOOTSTRAP_CONTAINER_NAME} {BOOTSTRAP_ENV_NAME}; deploy or refresh the ECS task definition before live validation"
        )
    try:
        payload_runtime_ids = _bootstrap_payload_runtime_ids(payload)
    except (json.JSONDecodeError, ValueError) as exc:
        return set(), (
            "bootstrap diagnostics: task definition bootstrap payload is invalid "
            f"({exc}); deploy a task definition with a valid source runtime bootstrap payload"
        )
    missing = sorted(requested_runtime_ids - payload_runtime_ids)
    present = sorted(requested_runtime_ids & payload_runtime_ids)
    status = "missing" if missing else "present"
    diagnostics = (
        "bootstrap diagnostics: "
        f"runtime={runtime_id} payload_status={status} "
        f"payload_runtime_count={len(payload_runtime_ids)} "
        f"requested_runtime_ids={','.join(sorted(requested_runtime_ids)) or '-'} "
        f"present_runtime_ids={','.join(present) or '-'} "
        f"missing_runtime_ids={','.join(missing) or '-'}"
    )
    if missing:
        diagnostics += (
            "; action=deploy or refresh source-runtime-bootstrap task definition/state "
            "so requested runtimes are bootstrapped before live validation"
        )
    return payload_runtime_ids, diagnostics


def _bootstrap_task_diagnostics(
    target: RuntimeTarget,
    task: dict[str, Any],
    messages: list[dict[str, Any]],
    region: str,
) -> str:
    lines: list[str] = []
    runtimes_listed_event = _latest_event(messages, "orchestrator.runtimes_listed")
    orchestrator_iteration_span = _latest_span(messages, "orchestrator.iteration")
    if runtimes_listed_event:
        lines.append(
            "runtime discovery log: "
            f"runtime_count={runtimes_listed_event.get('runtime_count', '-')}"
        )
    if orchestrator_iteration_span:
        lines.append(
            "runtime discovery iteration: "
            f"runtimes_attempted={orchestrator_iteration_span.get('runtimes_attempted', '-')}"
        )
    try:
        response = _aws(["ecs", "describe-task-definition", "--task-definition", task["taskDefinitionArn"]], region)
        _payload_ids, diagnostics = _bootstrap_payload_diagnostics(
            target.runtime_id,
            response.get("taskDefinition") or {},
            {target.runtime_id},
            region,
        )
        lines.append(diagnostics)
    except Exception as exc:
        lines.append(f"bootstrap diagnostics: unable to inspect task definition bootstrap payload ({exc})")
    try:
        bootstrap_messages = _task_logs(task, region, container_name=BOOTSTRAP_CONTAINER_NAME)
        summary = _summarize_log_messages(bootstrap_messages, limit=8)
        if summary:
            lines.append("source-runtime-bootstrap logs:\n" + summary)
        else:
            lines.append("source-runtime-bootstrap logs: no structured bootstrap log events found")
    except Exception as exc:
        lines.append(f"source-runtime-bootstrap logs: unavailable ({exc})")
    return _sanitize_text("\n".join(lines))[:6000]


def _verify_bootstrap_payload_targets(targets: list[RuntimeTarget], region: str) -> None:
    for target in targets:
        task_definition = _latest_active_task_definition(target.target["EcsParameters"]["TaskDefinitionArn"], region)
        response = _aws(["ecs", "describe-task-definition", "--task-definition", task_definition], region)
        target_payload = _target_bootstrap_payload(target)
        _payload_runtime_ids, diagnostics = (
            _bootstrap_payload_diagnostics_from_payload(target.runtime_id, target_payload, {target.runtime_id})
            if target_payload
            else _bootstrap_payload_diagnostics(
                target.runtime_id,
                response.get("taskDefinition") or {},
                {target.runtime_id},
                region,
            )
        )
        if f"missing_runtime_ids={target.runtime_id}" in diagnostics or "payload_status=missing" in diagnostics:
            raise RuntimeVerificationFailedError(
                target.runtime_id,
                "",
                "bootstrap payload",
                "missing",
                diagnostics,
            )
        if "bootstrap payload is invalid" in diagnostics:
            raise RuntimeVerificationFailedError(
                target.runtime_id,
                "",
                "bootstrap payload",
                "invalid",
                diagnostics,
            )
        if f"missing {BOOTSTRAP_CONTAINER_NAME}" in diagnostics:
            raise RuntimeVerificationFailedError(
                target.runtime_id,
                "",
                "bootstrap payload",
                "missing",
                diagnostics,
            )
        print(diagnostics, file=sys.stderr)


def _latest_span(messages: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for message in reversed(messages):
        if message.get("kind") == "span_end" and message.get("name") == name:
            return message
    return None


def _latest_event(messages: list[dict[str, Any]], *names: str) -> dict[str, Any] | None:
    wanted = set(names)
    for message in reversed(messages):
        if message.get("kind") == "event" and message.get("name") in wanted:
            return message
    return None


def _first_present(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _runtime_skip_reason(runtime_span: dict[str, Any] | None) -> str:
    if not runtime_span:
        return ""
    return str(runtime_span.get("reason") or "").strip()


def _runtime_skip_retryable(reason: str) -> bool:
    return reason == "lease_not_acquired"


def _failure_diagnostics(messages: list[dict[str, Any]], *spans: dict[str, Any] | None) -> str:
    span_ids = {id(span) for span in spans if span is not None}
    interesting = [
        message
        for message in messages
        if id(message) in span_ids or str(message.get("level") or "").lower() in {"error", "warn", "warning"}
    ]
    return _summarize_log_messages(interesting, limit=8)


def _verification_result_from_logs(
    target: RuntimeTarget,
    task_arn: str,
    exit_code: int | None,
    messages: list[dict[str, Any]],
    require_runtime_completed: bool,
    task: dict[str, Any] | None = None,
    region: str | None = None,
) -> VerificationResult | None:
    runtime_span = _latest_span(messages, "orchestrator.runtime")
    sync_span = _latest_span(messages, "source_runtime.sync")
    graph_ingest_span = _latest_span(messages, "orchestrator.graph_ingest")
    graph_runtime_span = _latest_span(messages, "graph.ingest_runtime")
    runtimes_listed_event = _latest_event(messages, "orchestrator.runtimes_listed")
    orchestrator_iteration_span = _latest_span(messages, "orchestrator.iteration")
    if (runtimes_listed_event or {}).get("runtime_count") == 0 or (orchestrator_iteration_span or {}).get("runtimes_attempted") == 0:
        diagnostics = ""
        if task is not None and region is not None:
            diagnostics = _bootstrap_task_diagnostics(target, task, messages, region)
        raise RuntimeVerificationFailedError(target.runtime_id, task_arn, "runtime discovery", "missing", diagnostics)
    runtime_status = str((runtime_span or {}).get("status") or "missing")
    sync_status = str((sync_span or {}).get("status") or "missing")
    graph_ingest_status = str((graph_ingest_span or {}).get("status") or "missing")
    if runtime_status == "skipped":
        raise RuntimeSkippedError(target.runtime_id, task_arn, _runtime_skip_reason(runtime_span))
    if sync_status == "failed":
        diagnostics = _failure_diagnostics(messages, sync_span, runtime_span)
        raise RuntimeVerificationFailedError(target.runtime_id, task_arn, "source sync", sync_status, diagnostics)
    if graph_ingest_status == "failed":
        diagnostics = _failure_diagnostics(messages, graph_ingest_span, graph_runtime_span, runtime_span)
        raise RuntimeVerificationFailedError(target.runtime_id, task_arn, "graph ingest", graph_ingest_status, diagnostics)
    if require_runtime_completed and runtime_status != "completed":
        raise RuntimeError(f"{target.runtime_id} orchestrator runtime status is {runtime_status}")
    if sync_status != "completed":
        if require_runtime_completed:
            raise RuntimeError(f"{target.runtime_id} source sync status is {sync_status}")
        return None
    if graph_ingest_status != "completed":
        if require_runtime_completed:
            raise RuntimeError(f"{target.runtime_id} graph ingest status is {graph_ingest_status}")
        return None
    contract_probe_event = _latest_event(messages, "source_runtime.contract_probe")
    contract_probe_status = str((contract_probe_event or {}).get("contract_probe_status") or "").strip().lower()
    if contract_probe_status in FAIL_CLOSED_CONTRACT_PROBE_STATUSES:
        raise RuntimeVerificationFailedError(target.runtime_id, task_arn, "contract probe", contract_probe_status)
    link_status_event = _latest_event(messages, "runtime.evidence.link_status", "source_runtime.link_status")
    link_status = str((link_status_event or {}).get("link_status") or "").strip().lower()
    if link_status in FAIL_CLOSED_LINK_STATUSES:
        raise RuntimeVerificationFailedError(target.runtime_id, task_arn, "link", link_status)

    return VerificationResult(
        runtime_id=target.runtime_id,
        task_arn=task_arn,
        exit_code=exit_code,
        runtime_status=runtime_status if runtime_status != "missing" else "running",
        sync_status=sync_status,
        graph_ingest_status=graph_ingest_status,
        events_appended=sync_span.get("events_appended") if sync_span else None,
        pages_read=sync_span.get("pages_read") if sync_span else None,
        entities_projected=_first_present(
            (graph_runtime_span or {}).get("entities_projected"),
            (graph_ingest_span or {}).get("entities_projected"),
            (sync_span or {}).get("entities_projected"),
        ),
        links_projected=_first_present(
            (graph_runtime_span or {}).get("links_projected"),
            (graph_ingest_span or {}).get("links_projected"),
            (sync_span or {}).get("links_projected"),
        ),
    )


def _verify_task(target: RuntimeTarget, task_arn: str, region: str) -> VerificationResult:
    task = _describe_tasks(target.target["Arn"], [task_arn], region)[0]
    containers = task.get("containers") or []
    cerebro_container = next((container for container in containers if container.get("name") == "cerebro"), None)
    bootstrap_container = next((container for container in containers if container.get("name") == BOOTSTRAP_CONTAINER_NAME), None)
    exit_code = cerebro_container.get("exitCode") if cerebro_container else None
    if exit_code != 0:
        stop_summary = _task_stop_summary(task)
        try:
            log_summary = _summarize_log_messages(_task_logs(task, region))
        except Exception as exc:
            log_summary = f"unable to fetch task logs: {exc}; ECS task stop: {stop_summary}"
        if bootstrap_container and bootstrap_container.get("exitCode") not in (None, 0):
            try:
                bootstrap_summary = _summarize_log_messages(_task_logs(task, region, container_name=BOOTSTRAP_CONTAINER_NAME))
                if bootstrap_summary:
                    bootstrap_detail = f"{BOOTSTRAP_CONTAINER_NAME} logs:\n{bootstrap_summary}"
                else:
                    raw_bootstrap_summary = _summarize_raw_log_messages(
                        _raw_task_log_messages(task, region, container_name=BOOTSTRAP_CONTAINER_NAME)
                    )
                    if raw_bootstrap_summary:
                        bootstrap_detail = f"{BOOTSTRAP_CONTAINER_NAME} raw logs:\n{raw_bootstrap_summary}"
                    else:
                        bootstrap_detail = f"{BOOTSTRAP_CONTAINER_NAME} logs: no structured bootstrap log events found"
            except Exception as exc:
                bootstrap_detail = f"{BOOTSTRAP_CONTAINER_NAME} logs: unavailable ({exc})"
            log_summary = f"{log_summary}\n{bootstrap_detail}" if log_summary else bootstrap_detail
        if stop_summary:
            log_summary = f"{log_summary}\nECS task stop: {stop_summary}" if log_summary else f"ECS task stop: {stop_summary}"
        raise RuntimeTaskFailedError(target.runtime_id, task_arn, exit_code, log_summary)

    messages = _task_logs(task, region)
    result = _verification_result_from_logs(target, task_arn, exit_code, messages, require_runtime_completed=True, task=task, region=region)
    if result is None:
        raise RuntimeError(f"{target.runtime_id} verification did not produce source sync and graph ingest spans")
    return result


def _verify_task_until_graph_ingested(
    target: RuntimeTarget,
    task_arn: str,
    timeout_seconds: int,
    poll_seconds: int,
    region: str,
) -> VerificationResult:
    task_id = "[redacted-task]"
    started = time.time()
    deadline = time.time() + timeout_seconds
    next_progress = 0.0
    last_task: dict[str, Any] | None = None
    last_log_error: Exception | None = None
    log_options_cache: dict[tuple[str, str], TaskLogOptions] = {}
    while time.time() < deadline:
        tasks = _describe_tasks(target.target["Arn"], [task_arn], region)
        task = tasks[0] if tasks else {}
        last_task = task
        status = str(task.get("lastStatus") or "UNKNOWN")
        containers = task.get("containers") or []
        cerebro_container = next((container for container in containers if container.get("name") == "cerebro"), None)
        exit_code = cerebro_container.get("exitCode") if cerebro_container else None
        messages: list[dict[str, Any]] = []
        if task and status in {"RUNNING", "STOPPED"}:
            try:
                messages = _task_logs(task, region, log_options_cache)
                last_log_error = None
            except Exception as exc:
                last_log_error = exc
        if messages:
            result = _verification_result_from_logs(target, task_arn, exit_code, messages, require_runtime_completed=False, task=task, region=region)
            if result is not None:
                print(
                    f"INFO: {target.runtime_id} source sync and graph ingest completed; task may continue finding-rule work",
                    file=sys.stderr,
                )
                return result
        if status == "STOPPED":
            if messages:
                result = _verification_result_from_logs(target, task_arn, exit_code, messages, require_runtime_completed=True, task=task, region=region)
                if result is not None:
                    return result
            if last_log_error is not None:
                raise RuntimeError(
                    f"unable to fetch stopped task logs for {target.runtime_id}: {last_log_error}; "
                    f"ECS task stop: {_task_stop_summary(task)}"
                ) from last_log_error
            return _verify_task(target, task_arn, region)
        now = time.time()
        if now >= next_progress:
            elapsed = int(now - started)
            width = 20
            progress = min(1.0, elapsed / max(1, timeout_seconds))
            filled = int(progress * width)
            bar = "#" * filled + "-" * (width - filled)
            print(
                f"WAIT source runtime graph ingest task={task_id} status={status} [{bar}] {elapsed}s/{timeout_seconds}s",
                file=sys.stderr,
                flush=True,
            )
            next_progress = now + max(30, poll_seconds)
        time.sleep(poll_seconds)
    if last_task is not None:
        try:
            messages = _task_logs(last_task, region, log_options_cache)
            result = _verification_result_from_logs(target, task_arn, None, messages, require_runtime_completed=False, task=last_task, region=region)
            if result is not None:
                return result
        except Exception:
            pass
    raise TimeoutError(f"task {_task_ref(task_arn)} did not complete source sync and graph ingest within {timeout_seconds} seconds")


def _run_and_verify_task_with_retries(
    target: RuntimeTarget,
    wait_timeout_seconds: int,
    poll_seconds: int,
    region: str,
    command_override: list[str] | None = None,
    allow_lease_contention_skip: bool = False,
    stop_running_before_run: bool = False,
    stop_timeout_seconds: int = 180,
    failed_run_retry_seconds: int = 0,
    run_attempt_timeout_seconds: int = 0,
    succeed_after_graph_ingest: bool = False,
    bootstrap_runtime_ids: tuple[str, ...] = (),
) -> VerificationResult:
    if stop_running_before_run:
        _stop_running_tasks(
            target,
            region,
            "Cerebro deploy verification is replacing a stuck source-runtime task",
            stop_timeout_seconds,
            poll_seconds,
        )
    start = time.time()
    deadline = start + wait_timeout_seconds
    failed_run_retry_deadline = start + failed_run_retry_seconds if failed_run_retry_seconds > 0 else None
    while True:
        remaining = max(1, int(deadline - time.time()))
        task_arn = _run_task(target, region, command_override, bootstrap_runtime_ids)
        attempt_timeout = min(remaining, run_attempt_timeout_seconds) if run_attempt_timeout_seconds > 0 else remaining
        try:
            if succeed_after_graph_ingest:
                return _verify_task_until_graph_ingested(target, task_arn, attempt_timeout, poll_seconds, region)
            else:
                _wait_for_task(target.target["Arn"], task_arn, attempt_timeout, poll_seconds, region)
                return _verify_task(target, task_arn, region)
        except TimeoutError:
            now = time.time()
            if failed_run_retry_deadline is None or now >= failed_run_retry_deadline:
                raise
            remaining = int(deadline - now)
            if remaining <= poll_seconds:
                raise
            _stop_task(
                target,
                task_arn,
                region,
                "Cerebro deploy verification attempt timed out",
                stop_timeout_seconds,
                poll_seconds,
            )
            print(
                f"WARNING: {target.runtime_id} verification task timed out; retrying verification task",
                file=sys.stderr,
            )
            time.sleep(min(poll_seconds, remaining))
        except RuntimeSkippedError as exc:
            if not _runtime_skip_retryable(exc.reason):
                raise
            if allow_lease_contention_skip:
                print(
                    f"WARNING: {target.runtime_id} skipped due to {exc.reason}; treating as already busy",
                    file=sys.stderr,
                )
                return VerificationResult(
                    runtime_id=target.runtime_id,
                    task_arn=task_arn,
                    exit_code=0,
                    runtime_status="skipped",
                    sync_status="skipped",
                    graph_ingest_status="skipped",
                    events_appended=None,
                    pages_read=None,
                )
            remaining = int(deadline - time.time())
            if remaining <= poll_seconds:
                raise RuntimeError(
                    f"{target.runtime_id} kept skipping due to {exc.reason} before verification timeout"
                ) from exc
            print(
                f"WARNING: {target.runtime_id} skipped due to {exc.reason}; retrying verification task",
                file=sys.stderr,
            )
            time.sleep(min(poll_seconds, remaining))
        except (RuntimeTaskFailedError, RuntimeVerificationFailedError):
            now = time.time()
            if failed_run_retry_deadline is None or now >= failed_run_retry_deadline:
                raise
            remaining = int(deadline - now)
            if remaining <= poll_seconds:
                raise
            print(
                f"WARNING: {target.runtime_id} verification task failed; retrying verification task",
                file=sys.stderr,
            )
            time.sleep(min(poll_seconds, remaining))


def _verify_account(stack: str, region: str) -> None:
    expected = EXPECTED_STACK_ACCOUNTS.get(stack)
    if not expected:
        return
    caller = _aws(["sts", "get-caller-identity"], region)
    actual = str(caller.get("Account", ""))
    if actual != expected:
        raise RuntimeError(f"stack {stack} is using an unexpected AWS account; check AWS_PROFILE")


def _secret_import_preflight_findings(
    config: dict[str, Any],
    stack: str,
    region: str,
) -> list[SecretImportPreflightFinding]:
    imports = secret_imports.expected_secret_imports(config, stack)
    by_index = {index: item for index, item in enumerate(imports, start=1)}
    findings: list[SecretImportPreflightFinding] = []
    for finding in secret_imports.verify_secret_imports(imports, region):
        item = by_index.get(finding.index)
        if item is None:
            findings.append(
                SecretImportPreflightFinding(
                    env_name="unknown",
                    key_path="unknown",
                    category=str(finding.category),
                    reason=str(finding.reason),
                )
            )
            continue
        findings.append(
            SecretImportPreflightFinding(
                env_name=item.env_name,
                key_path=item.secret_id,
                category=str(finding.category),
                reason=str(finding.reason),
            )
        )

    declared = {item.env_name for item in imports}
    for env_name in secret_imports._source_runtime_env_refs(config.get("sourceRuntimes") or []):
        if env_name not in declared:
            findings.append(
                SecretImportPreflightFinding(
                    env_name=env_name,
                    key_path="undeclared",
                    category="runtime-env-ref",
                    reason="undeclared",
                )
            )
    return findings


def _source_secret_key_env_name(secret_key: Any) -> str:
    return source_runtime_scope.source_secret_key_env_name(secret_key)


def _config_for_runtime_scope(config: dict[str, Any], runtime_ids: set[str]) -> dict[str, Any]:
    return source_runtime_scope.config_for_runtime_scope(config, runtime_ids)


def _print_secret_import_preflight_failure(
    stack: str,
    findings: list[SecretImportPreflightFinding],
) -> None:
    print(
        f"{stack} AWS secret import preflight failed for {len(findings)} import(s); ECS run-task was not started.",
        file=sys.stderr,
    )
    print("key_path\tenv_key\tcategory\treason", file=sys.stderr)
    for finding in findings:
        print(
            "\t".join(
                [
                    _sanitize_text(finding.key_path),
                    _sanitize_text(finding.env_name),
                    _sanitize_text(finding.category),
                    _sanitize_text(finding.reason),
                ]
            ),
            file=sys.stderr,
        )
    print(
        "Infisical guidance: use read-only key-presence checks only, never --plain or value-printing output, "
        "then sync the missing keys into AWS Secrets Manager before rerunning live validation.",
        file=sys.stderr,
    )


def _verify_secret_import_preflight(config: dict[str, Any], stack: str, region: str) -> None:
    findings = _secret_import_preflight_findings(config, stack, region)
    if not findings:
        print(f"{stack} AWS secret import preflight passed.")
        return
    _print_secret_import_preflight_failure(stack, findings)
    raise RuntimeError("required AWS secret imports are missing; ECS run-task was not started")


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


def _effective_source_id(source_id: str | None, requested_runtime_ids: set[str]) -> str:
    if source_id is not None:
        return source_id
    return "" if requested_runtime_ids else "cosmo"


def _print_dry_run_plan(
    stack: str,
    environment: str,
    source_id: str,
    families: set[str],
    requested: set[str],
    runtime_ids: list[str],
    targets: list[RuntimeTarget],
    options: VerificationOptions,
    target_concurrency: int,
    observability_targets: bool,
    allow_missing_targets: bool,
    disabled_runtime_ids: list[str] | None = None,
) -> None:
    disabled = set(disabled_runtime_ids or [])
    target_by_runtime = {target.runtime_id: target for target in targets}
    print("mode\tread_only_dry_run")
    print(f"stack\t{stack}")
    print(f"environment\t{environment}")
    print(f"source_id\t{source_id}")
    print(f"families\t{','.join(sorted(families)) if families else '*'}")
    print(f"requested_runtime_ids\t{','.join(sorted(requested)) if requested else '*'}")
    print(f"observability_targets\t{str(observability_targets).lower()}")
    print(f"mutations\tnone")
    print(f"run_requested\t{str(options.run).lower()}")
    print(f"wait_timeout_seconds\t{options.wait_timeout_seconds}")
    print(f"poll_seconds\t{options.poll_seconds}")
    print(f"max_age_minutes\t{options.max_age_minutes}")
    print(f"run_page_limit\t{options.run_page_limit if options.run_page_limit is not None else '-'}")
    print(f"run_graph_page_limit\t{options.run_graph_page_limit if options.run_graph_page_limit is not None else '-'}")
    print(f"run_event_limit\t{options.run_event_limit if options.run_event_limit is not None else '-'}")
    print(f"run_attempt_timeout_seconds\t{options.run_attempt_timeout_seconds}")
    print(f"failed_run_retry_seconds\t{options.failed_run_retry_seconds}")
    print(f"allow_missing_targets\t{str(allow_missing_targets).lower()}")
    print(f"target_concurrency\t{target_concurrency}")
    print("runtime_id\tschedule\trule\tstatus")
    for runtime_id in runtime_ids:
        target = target_by_runtime.get(runtime_id)
        if runtime_id in disabled:
            print(f"{runtime_id}\t-\t-\tdisabled")
        elif target is None:
            print(f"{runtime_id}\t-\t-\tmissing_target")
        else:
            print(f"{runtime_id}\t{target.schedule_name}\t{target.rule_name}\tplanned")


def _verify_runtime_target(target: RuntimeTarget, options: VerificationOptions) -> VerificationResult:
    if options.run:
        command_override = _verification_command(
            target.runtime_id,
            options.run_page_limit,
            options.run_graph_page_limit,
            options.run_event_limit,
        )
        return _run_and_verify_task_with_retries(
            target,
            options.wait_timeout_seconds,
            options.poll_seconds,
            options.region,
            command_override,
            options.allow_lease_contention_skip,
            options.stop_running_before_run,
            options.stop_timeout_seconds,
            options.failed_run_retry_seconds,
            options.run_attempt_timeout_seconds,
            options.succeed_after_graph_ingest,
            (target.runtime_id,) if options.bootstrap_runtime_ids else (),
        )
    task_arn = _latest_task(target, options.max_age_minutes, options.region)
    return _verify_task(target, task_arn, options.region)


def _verify_runtime_targets(
    targets: list[RuntimeTarget],
    options: VerificationOptions,
    target_concurrency: int,
) -> list[VerificationResult]:
    if target_concurrency <= 1 or len(targets) <= 1:
        return [_verify_runtime_target(target, options) for target in targets]

    results: list[VerificationResult | None] = [None] * len(targets)
    with ThreadPoolExecutor(max_workers=min(target_concurrency, len(targets))) as executor:
        future_indexes = {
            executor.submit(_verify_runtime_target, target, options): index
            for index, target in enumerate(targets)
        }
        for future in as_completed(future_indexes):
            results[future_indexes[future]] = future.result()
    return [result for result in results if result is not None]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify ECS source runtime executions from GitOps-declared schedules.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--source-id")
    parser.add_argument("--runtime-id", action="append", default=[])
    parser.add_argument("--family", action="append", default=[], help="Restrict verification to source runtimes with this config family.")
    parser.add_argument("--observability-targets", action="store_true", help="Select enabled sourceRuntimeObservability runtimes instead of all sourceRuntimes for the source-id/family scope.")
    parser.add_argument("--dry-run", action="store_true", help="Read-only discovery mode: report planned targets, bounds, and checks without starting tasks or inspecting task logs.")
    parser.add_argument("--run", action="store_true", help="Start each runtime from its EventBridge target before verifying. Without --run, verifies recent stopped tasks only.")
    parser.add_argument("--run-page-limit", type=_positive_int, help="Override page_limit for tasks started by --run.")
    parser.add_argument("--run-graph-page-limit", type=_positive_int, help="Override graph_page_limit for tasks started by --run.")
    parser.add_argument("--run-event-limit", type=_positive_int, help="Override event_limit for tasks started by --run.")
    parser.add_argument(
        "--allow-lease-contention-skip",
        action="store_true",
        help="Treat lease_not_acquired skips as non-fatal when another runtime task is already active.",
    )
    parser.add_argument("--stop-running-before-run", action="store_true", help="Stop already-running tasks for the target runtime family before starting --run verification.")
    parser.add_argument("--stop-timeout-seconds", type=_positive_int, default=180)
    parser.add_argument("--max-age-minutes", type=_positive_int, default=180)
    parser.add_argument("--failed-run-retry-seconds", type=_non_negative_int, default=0, help="Retry failed verification tasks for this many seconds before failing.")
    parser.add_argument("--run-attempt-timeout-seconds", type=_non_negative_int, default=0, help="Stop and retry a --run verification task if one attempt runs longer than this.")
    parser.add_argument(
        "--succeed-after-graph-ingest",
        action="store_true",
        help="For --run, return after source sync and graph ingest complete instead of waiting for post-ingest work.",
    )
    parser.add_argument("--wait-timeout-seconds", type=_positive_int, default=3600)
    parser.add_argument("--poll-seconds", type=_positive_int, default=10)
    parser.add_argument("--target-concurrency", type=_positive_int, default=1, help="Verify up to this many source runtime targets concurrently.")
    parser.add_argument("--allow-missing-targets", action="store_true", help="Skip declared runtimes whose EventBridge target is not deployed yet.")
    args = parser.parse_args(argv)

    stack = _stack_name(args.stack_file)
    config = _load_config(args.stack_file)
    environment = str(config.get("environment") or stack)
    resource_prefix = f"cerebro-{environment}"
    requested = set(args.runtime_id or [])
    families = set(args.family or [])
    source_id = _effective_source_id(args.source_id, requested)
    if args.observability_targets:
        runtime_ids = _observability_runtime_ids(config, source_id, requested, families)
    else:
        runtime_ids = _declared_runtime_ids(config, source_id, requested, families)
    if not runtime_ids:
        disabled_runtime_ids = (
            _disabled_observability_runtime_ids(config, source_id, requested, families)
            if args.observability_targets and args.dry_run
            else []
        )
        if disabled_runtime_ids:
            options = VerificationOptions(
                run=args.run,
                wait_timeout_seconds=args.wait_timeout_seconds,
                poll_seconds=args.poll_seconds,
                region=args.region,
                run_page_limit=args.run_page_limit,
                run_graph_page_limit=args.run_graph_page_limit,
                run_event_limit=args.run_event_limit,
                allow_lease_contention_skip=args.allow_lease_contention_skip,
                stop_running_before_run=args.stop_running_before_run,
                stop_timeout_seconds=args.stop_timeout_seconds,
                failed_run_retry_seconds=args.failed_run_retry_seconds,
                run_attempt_timeout_seconds=args.run_attempt_timeout_seconds,
                succeed_after_graph_ingest=args.succeed_after_graph_ingest,
                max_age_minutes=args.max_age_minutes,
            )
            _print_dry_run_plan(
                stack,
                environment,
                source_id,
                families,
                requested,
                disabled_runtime_ids,
                [],
                options,
                args.target_concurrency,
                args.observability_targets,
                args.allow_missing_targets,
                disabled_runtime_ids,
            )
            return 0
        scope = f" source {source_id!r}" if source_id else ""
        if families:
            scope += f"{' and' if scope else ''} family {', '.join(sorted(families))!r}"
        source = "sourceRuntimeObservability runtimes" if args.observability_targets else "source runtimes"
        raise RuntimeError(f"no enabled declared {source} found for{scope}")

    _verify_account(stack, args.region)
    targets = _runtime_targets(config, runtime_ids, resource_prefix, args.region, args.allow_missing_targets)
    if not targets:
        if args.dry_run and args.allow_missing_targets:
            options = VerificationOptions(
                run=args.run,
                wait_timeout_seconds=args.wait_timeout_seconds,
                poll_seconds=args.poll_seconds,
                region=args.region,
                run_page_limit=args.run_page_limit,
                run_graph_page_limit=args.run_graph_page_limit,
                run_event_limit=args.run_event_limit,
                allow_lease_contention_skip=args.allow_lease_contention_skip,
                stop_running_before_run=args.stop_running_before_run,
                stop_timeout_seconds=args.stop_timeout_seconds,
                failed_run_retry_seconds=args.failed_run_retry_seconds,
                run_attempt_timeout_seconds=args.run_attempt_timeout_seconds,
                succeed_after_graph_ingest=args.succeed_after_graph_ingest,
                max_age_minutes=args.max_age_minutes,
            )
            _print_dry_run_plan(
                stack,
                environment,
                source_id,
                families,
                requested,
                runtime_ids,
                [],
                options,
                args.target_concurrency,
                args.observability_targets,
                args.allow_missing_targets,
                _disabled_observability_runtime_ids(config, source_id, requested, families) if args.observability_targets else [],
            )
            return 0
        if args.allow_missing_targets and not args.observability_targets:
            print("No deployed source runtime targets matched the requested scope.")
            return 0
        raise RuntimeError("no deployed source runtime targets matched the requested scope")
    options = VerificationOptions(
        run=args.run,
        wait_timeout_seconds=args.wait_timeout_seconds,
        poll_seconds=args.poll_seconds,
        region=args.region,
        run_page_limit=args.run_page_limit,
        run_graph_page_limit=args.run_graph_page_limit,
        run_event_limit=args.run_event_limit,
        allow_lease_contention_skip=args.allow_lease_contention_skip,
        stop_running_before_run=args.stop_running_before_run,
        stop_timeout_seconds=args.stop_timeout_seconds,
        failed_run_retry_seconds=args.failed_run_retry_seconds,
        run_attempt_timeout_seconds=args.run_attempt_timeout_seconds,
        succeed_after_graph_ingest=args.succeed_after_graph_ingest,
        max_age_minutes=args.max_age_minutes,
        bootstrap_runtime_ids=tuple(runtime_ids),
    )
    if args.dry_run:
        _print_dry_run_plan(
            stack,
            environment,
            source_id,
            families,
            requested,
            runtime_ids,
            targets,
            options,
            args.target_concurrency,
            args.observability_targets,
            args.allow_missing_targets,
            _disabled_observability_runtime_ids(config, source_id, requested, families) if args.observability_targets else [],
        )
        return 0
    _verify_bootstrap_payload_targets(targets, args.region)
    if args.run:
        preflight_config = _config_for_runtime_scope(config, set(runtime_ids))
        _verify_secret_import_preflight(preflight_config, stack, args.region)
    results = _verify_runtime_targets(
        targets,
        options,
        args.target_concurrency,
    )

    print("runtime_id\texit\tsync\tevents_appended\tpages_read\tgraph_ingest\tentities_projected\tlinks_projected\ttask_ref")
    for result in results:
        print(
            "\t".join(
                [
                    result.runtime_id,
                    str(result.exit_code),
                    result.sync_status,
                    str(result.events_appended),
                    str(result.pages_read),
                    result.graph_ingest_status,
                    str(result.entities_projected),
                    str(result.links_projected),
                    _task_ref(result.task_arn),
                ]
            )
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
