#!/usr/bin/env python3
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any

try:
    from aws import source_runtime_scope
except ModuleNotFoundError:  # pragma: no cover - used when executed as scripts/verify_graph_health_ecs.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from aws import source_runtime_scope


EXPECTED_STACK_ACCOUNTS = {
    "sec-dev": "944130631940",
    "go-prod": "837279440628",
}
DEFAULT_MAX_RUNNING_MINUTES = 60
DEFAULT_WAIT_TIMEOUT_SECONDS = 3600
DEFAULT_GRAPH_COMMAND_RETRY_SECONDS = 1800
DEFAULT_CREDENTIAL_SAFE_TIMEOUT_SECONDS = 3300
DEFAULT_LOG_WAIT_SECONDS = 60
DEFAULT_LOG_POLL_SECONDS = 2
MAX_ECS_CONTAINER_OVERRIDES_BYTES = 8192
MIN_INGEST_RUN_LIMIT = 100
INGEST_RUN_LIMIT_MULTIPLIER = 20
MAX_INGEST_RUN_LIMIT = 500
ATTACK_PATH_RELATION_MIN_TAG = (2, 1, 46)
RELATION_COUNT_MIN_TAG = (2, 1, 50)
GRAPH_HEALTH_COMMAND_MIN_TAG = (2, 1, 140)
REQUIRED_RELATIONS = {"belongs_to", "represents"}
AWS_CAN_REACH_REQUIRED_FAMILIES = {"resource_exposure"}
AWS_CAN_ASSUME_REQUIRED_FAMILIES = {"iam_role_trust"}
AWS_CAN_PERFORM_REQUIRED_FAMILIES = {"effective_permission"}
AWS_ATTACK_PATH_RELATIONS = {"can_perform", "can_assume", "can_admin", "can_impersonate"}
GRAPH_RELATIONS_TO_OBSERVE = AWS_ATTACK_PATH_RELATIONS | {"can_reach", "runs_as"}
INGEST_RUN_ERROR_DETAIL_LIMIT = 500
GRAPH_COMMAND_TASK_FAMILY_SUFFIX = "-graph-command"
REGISTER_TASK_DEFINITION_KEYS = (
    "taskRoleArn",
    "executionRoleArn",
    "networkMode",
    "containerDefinitions",
    "volumes",
    "placementConstraints",
    "requiresCompatibilities",
    "cpu",
    "memory",
    "pidMode",
    "ipcMode",
    "proxyConfiguration",
    "inferenceAccelerators",
    "ephemeralStorage",
    "runtimePlatform",
    "enableFaultInjection",
)


@dataclass(frozen=True)
class GraphCommandResult:
    command: list[str]
    task_arn: str
    exit_code: int | None
    payload: dict[str, Any]


@dataclass(frozen=True)
class GraphCommandContext:
    cluster: str
    task_definition: str
    network_configuration: dict[str, Any]
    log_group: str
    stream_prefix: str
    has_source_runtime_bootstrap: bool
    task_definition_without_bootstrap: dict[str, Any] | None = None


class CurrentIngestRunsError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool) -> None:
        self.retryable = retryable
        super().__init__(message)


def _stack_name(path: Path) -> str:
    name = path.name
    if name.startswith("Pulumi.") and name.endswith(".yaml"):
        return name.removeprefix("Pulumi.").removesuffix(".yaml")
    return path.stem


def _load_config(path: Path) -> dict[str, Any]:
    return source_runtime_scope.load_cerebro_config(path)


def _resource_prefix(config: dict[str, Any], stack: str) -> str:
    environment = str(config.get("environment") or stack).strip()
    if not environment:
        raise ValueError("cerebro:environment is required")
    return f"cerebro-{environment}"


def _declared_runtime_ids(config: dict[str, Any]) -> set[str]:
    return set(source_runtime_scope.declared_runtime_ids(config))


def _declared_aws_families(config: dict[str, Any]) -> set[str]:
    return source_runtime_scope.declared_aws_families(config)


def _ingest_run_limit(declared_runtime_ids: set[str]) -> int:
    return min(MAX_INGEST_RUN_LIMIT, max(MIN_INGEST_RUN_LIMIT, len(declared_runtime_ids) * INGEST_RUN_LIMIT_MULTIPLIER))


def _image_tag_version(value: Any) -> tuple[int, int, int] | None:
    match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$", str(value or "").strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _supports_attack_path_relations(config: dict[str, Any]) -> bool:
    version = _image_tag_version(config.get("imageTag"))
    return bool(version and version >= ATTACK_PATH_RELATION_MIN_TAG)


def _supports_relation_counts(config: dict[str, Any]) -> bool:
    version = _image_tag_version(config.get("imageTag"))
    return bool(version and version >= RELATION_COUNT_MIN_TAG)


def _supports_graph_health_command(config: dict[str, Any]) -> bool:
    version = _image_tag_version(config.get("imageTag"))
    return bool(version and version >= GRAPH_HEALTH_COMMAND_MIN_TAG)


def _aws(args: list[str], region: str) -> Any:
    command = ["aws", *args, "--region", region, "--output", "json"]
    try:
        completed = subprocess.run(command, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        message = f"{' '.join(command)} failed with exit code {exc.returncode}"
        if detail:
            message = f"{message}: {detail}"
        raise RuntimeError(message) from exc
    if not completed.stdout.strip():
        return None
    return json.loads(completed.stdout)


def _verify_account(stack: str, region: str) -> None:
    expected = EXPECTED_STACK_ACCOUNTS.get(stack)
    if not expected:
        return
    caller = _aws(["sts", "get-caller-identity"], region)
    actual = str(caller.get("Account", ""))
    if actual != expected:
        raise RuntimeError(f"stack {stack} must run in AWS account {expected}, got {actual}")


def _describe_api_service(resource_prefix: str, region: str) -> dict[str, Any]:
    cluster = f"{resource_prefix}-cluster"
    service_name = f"{resource_prefix}-api"
    response = _aws(["ecs", "describe-services", "--cluster", cluster, "--services", service_name], region)
    failures = response.get("failures") or []
    if failures:
        raise RuntimeError(f"failed to describe {service_name}: {failures}")
    services = response.get("services") or []
    if len(services) != 1:
        raise RuntimeError(f"expected one service named {service_name}, got {len(services)}")
    service = services[0]
    if service.get("status") != "ACTIVE":
        raise RuntimeError(f"{service_name} status is {service.get('status')}")
    return service


def _network_configuration(service: dict[str, Any]) -> dict[str, Any]:
    network = ((service.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {}).copy()
    if not network.get("subnets") or not network.get("securityGroups"):
        raise RuntimeError("API service is missing awsvpc network configuration")
    return {
        "awsvpcConfiguration": {
            "subnets": network["subnets"],
            "securityGroups": network["securityGroups"],
            "assignPublicIp": network.get("assignPublicIp", "DISABLED"),
        }
    }


def _task_id(task_arn: str) -> str:
    return task_arn.rsplit("/", 1)[-1]


def _describe_tasks(cluster: str, task_arns: list[str], region: str) -> list[dict[str, Any]]:
    response = _aws(["ecs", "describe-tasks", "--cluster", cluster, "--tasks", *task_arns], region)
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
    return "; ".join(parts)[:2000]


def _latest_active_task_definition(task_definition: str, region: str) -> str:
    response = _aws(["ecs", "describe-task-definition", "--task-definition", task_definition], region)
    definition = response.get("taskDefinition") or {}
    if definition.get("status") == "ACTIVE":
        return str(definition.get("taskDefinitionArn") or task_definition)
    family = str(definition.get("family") or task_definition.rsplit("/", 1)[-1].rsplit(":", 1)[0]).strip()
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
    print(f"Using latest active ECS task definition {replacement} instead of inactive {task_definition}", file=sys.stderr)
    return replacement


def _task_definition_container_names(task_definition: str, region: str) -> set[str]:
    response = _aws(["ecs", "describe-task-definition", "--task-definition", task_definition], region)
    return {
        str(container.get("name") or "").strip()
        for container in (response.get("taskDefinition") or {}).get("containerDefinitions") or []
        if str(container.get("name") or "").strip()
    }


def _graph_command_overrides_from_names(command: list[str], container_names: set[str]) -> dict[str, Any]:
    return {"containerOverrides": [{"name": "cerebro", "command": command}]}


def _graph_command_overrides(task_definition: str, command: list[str], region: str) -> dict[str, Any]:
    return _graph_command_overrides_from_names(command, _task_definition_container_names(task_definition, region))


def _graph_command_family(family: str) -> str:
    if family.endswith(GRAPH_COMMAND_TASK_FAMILY_SUFFIX):
        return family
    return f"{family[: 255 - len(GRAPH_COMMAND_TASK_FAMILY_SUFFIX)]}{GRAPH_COMMAND_TASK_FAMILY_SUFFIX}"


def _task_definition_without_bootstrap_from_definition(task_definition: dict[str, Any]) -> dict[str, Any] | None:
    containers = task_definition.get("containerDefinitions") or []
    if not any(container.get("name") == "source-runtime-bootstrap" for container in containers):
        return None
    graph_containers: list[dict[str, Any]] = []
    for container in containers:
        if container.get("name") == "source-runtime-bootstrap":
            continue
        updated = dict(container)
        depends_on = [
            dependency
            for dependency in (updated.get("dependsOn") or [])
            if dependency.get("containerName") != "source-runtime-bootstrap"
        ]
        if depends_on:
            updated["dependsOn"] = depends_on
        else:
            updated.pop("dependsOn", None)
        graph_containers.append(updated)
    if not graph_containers:
        raise RuntimeError("task definition contains no containers after removing source-runtime-bootstrap")
    family = str(task_definition.get("family") or "").strip()
    if not family:
        raise RuntimeError("task definition is missing family")
    payload = {
        key: task_definition[key]
        for key in REGISTER_TASK_DEFINITION_KEYS
        if key in task_definition and task_definition[key] not in (None, [], {})
    }
    payload["family"] = _graph_command_family(family)
    payload["containerDefinitions"] = graph_containers
    return payload


def _task_definition_without_bootstrap(task_definition: str, region: str) -> dict[str, Any] | None:
    response = _aws(["ecs", "describe-task-definition", "--task-definition", task_definition], region)
    return _task_definition_without_bootstrap_from_definition(response.get("taskDefinition") or {})


def _register_graph_command_task_definition(payload: dict[str, Any], region: str) -> str:
    response = _aws(["ecs", "register-task-definition", "--cli-input-json", json.dumps(payload, separators=(",", ":"))], region)
    arn = str(((response or {}).get("taskDefinition") or {}).get("taskDefinitionArn") or "").strip()
    if not arn:
        raise RuntimeError("register-task-definition did not return a taskDefinitionArn")
    print(f"Using temporary graph command ECS task definition {arn}", file=sys.stderr)
    return arn


def _deregister_graph_command_task_definition(task_definition: str, region: str) -> None:
    try:
        _aws(["ecs", "deregister-task-definition", "--task-definition", task_definition], region)
    except Exception as exc:
        print(f"WARNING: failed to deregister temporary graph command task definition {task_definition}: {exc}", file=sys.stderr)


def _graph_command_context(resource_prefix: str, service: dict[str, Any], region: str) -> GraphCommandContext:
    task_definition = _latest_active_task_definition(service["taskDefinition"], region)
    response = _aws(["ecs", "describe-task-definition", "--task-definition", task_definition], region)
    task_definition_payload = response["taskDefinition"]
    container_definitions = task_definition_payload["containerDefinitions"]
    container_names = {
        str(container.get("name") or "").strip()
        for container in container_definitions
        if str(container.get("name") or "").strip()
    }
    cerebro_container = next(container for container in container_definitions if container.get("name") == "cerebro")
    options = cerebro_container["logConfiguration"]["options"]
    return GraphCommandContext(
        cluster=f"{resource_prefix}-cluster",
        task_definition=task_definition,
        network_configuration=_network_configuration(service),
        log_group=options["awslogs-group"],
        stream_prefix=options["awslogs-stream-prefix"],
        has_source_runtime_bootstrap="source-runtime-bootstrap" in container_names,
        task_definition_without_bootstrap=_task_definition_without_bootstrap_from_definition(task_definition_payload),
    )


def _wait_for_task(cluster: str, task_arn: str, timeout_seconds: int, poll_seconds: int, region: str) -> None:
    task_id = _task_id(task_arn)
    started = time.time()
    deadline = time.time() + timeout_seconds
    next_progress = 0.0
    while True:
        tasks = _describe_tasks(cluster, [task_arn], region)
        status = str(tasks[0].get("lastStatus") or "UNKNOWN") if tasks else "UNKNOWN"
        if status == "STOPPED":
            if tasks:
                print(f"INFO graph command task={task_id} stopped: {_task_stop_summary(tasks[0])}", file=sys.stderr)
            return
        now = time.time()
        if now >= deadline:
            break
        if now >= next_progress:
            elapsed = int(now - started)
            width = 20
            progress = min(1.0, elapsed / max(1, timeout_seconds))
            filled = int(progress * width)
            bar = "#" * filled + "-" * (width - filled)
            print(
                f"WAIT graph command task={task_id} status={status} [{bar}] {elapsed}s/{timeout_seconds}s",
                file=sys.stderr,
                flush=True,
            )
            next_progress = now + max(30, poll_seconds)
        time.sleep(min(poll_seconds, max(1, int(deadline - now))))
    raise TimeoutError(f"task {task_arn} did not stop within {timeout_seconds} seconds")


def _log_options(task_definition: str, region: str) -> tuple[str, str]:
    response = _aws(["ecs", "describe-task-definition", "--task-definition", task_definition], region)
    containers = response["taskDefinition"]["containerDefinitions"]
    container = next(item for item in containers if item.get("name") == "cerebro")
    options = container["logConfiguration"]["options"]
    return options["awslogs-group"], options["awslogs-stream-prefix"]


def _task_messages(
    task: dict[str, Any],
    region: str,
    log_options: tuple[str, str] | None = None,
) -> list[str]:
    log_group, stream_prefix = log_options if log_options is not None else _log_options(task["taskDefinitionArn"], region)
    stream = f"{stream_prefix}/cerebro/{_task_id(task['taskArn'])}"
    events = _aws(
        [
            "logs",
            "get-log-events",
            "--log-group-name",
            log_group,
            "--log-stream-name",
            stream,
            "--limit",
            "10000",
            "--start-from-head",
        ],
        region,
    )
    return [str(event.get("message") or "") for event in events.get("events") or []]


def _wait_for_task_messages(fetch_messages, timeout_seconds: int = DEFAULT_LOG_WAIT_SECONDS) -> list[str]:
    deadline = time.time() + timeout_seconds
    messages: list[str] = []
    last_error: Exception | None = None
    while True:
        try:
            messages = fetch_messages()
            last_error = None
        except Exception as exc:
            if not _is_missing_log_stream_error(exc):
                raise
            last_error = exc
            messages = []
        if any(message.strip() for message in messages):
            return messages
        now = time.time()
        if now >= deadline:
            if last_error is not None:
                raise TimeoutError(f"task log stream was not available after {timeout_seconds}s: {last_error}") from last_error
            return messages
        time.sleep(min(DEFAULT_LOG_POLL_SECONDS, max(1, int(deadline - now))))


def _is_missing_log_stream_error(error: Exception) -> bool:
    text = str(error).lower()
    return "specified log stream does not exist" in text or "resourcenotfoundexception" in text


def _is_span_log_message(message: str) -> bool:
    text = message.strip()
    if not text.startswith("{") or not text.endswith("}"):
        return False
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return False
    return isinstance(payload, dict) and str(payload.get("kind") or "").startswith("span_")


def _log_tail(messages: list[str], limit: int = 1000) -> str:
    text = "\n".join(message for message in messages if message.strip())
    return _truncate_detail(text[-limit:], limit)


def _extract_json_payload(messages: list[str]) -> dict[str, Any]:
    text = "\n".join(message for message in messages if message.strip() and not _is_span_log_message(message))
    decoder = json.JSONDecoder()
    candidates: list[dict[str, Any]] = []
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            payload, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            candidates.append(payload)
    if not candidates:
        raise ValueError(f"graph command did not emit a JSON object: {text[-500:]}")
    for payload in reversed(candidates):
        if _looks_like_graph_health_payload(payload):
            return payload
    for payload in reversed(candidates):
        if _looks_like_graph_command_payload(payload):
            return payload
    return candidates[-1]


def _looks_like_graph_health_payload(payload: dict[str, Any]) -> bool:
    return "status" in payload and "counts" in payload and "integrity" in payload


def _looks_like_graph_command_payload(payload: dict[str, Any]) -> bool:
    if _looks_like_graph_health_payload(payload):
        return True
    if "nodes" in payload and "relations" in payload:
        return True
    if "checks" in payload or "runs" in payload:
        return True
    if "patterns" in payload or "traversals" in payload or "topology" in payload:
        return True
    return isinstance(payload.get("relations"), dict)


def _credential_safe_timeout(overall_deadline: float | None, timeout_seconds: int) -> int:
    if overall_deadline is None:
        return timeout_seconds
    remaining = int(overall_deadline - time.time())
    if remaining <= 0:
        raise TimeoutError("graph health verification reached credential-safe timeout before AWS credentials can expire")
    return min(timeout_seconds, remaining)


def _extract_graph_payload_or_raise(command: list[str], task_arn: str, messages: list[str]) -> dict[str, Any]:
    try:
        return _extract_json_payload(messages)
    except Exception as exc:
        raise RuntimeError(
            f"graph command {' '.join(command)} did not emit valid JSON for {task_arn}: {exc}; "
            f"log tail: {_log_tail(messages)}"
        ) from exc


def _extract_graph_payload_with_retries(command: list[str], task_arn: str, fetch_messages) -> tuple[list[str], dict[str, Any]]:
    deadline = time.time() + DEFAULT_LOG_WAIT_SECONDS
    messages: list[str] = []
    last_error: Exception | None = None
    while True:
        try:
            messages = fetch_messages()
        except Exception as exc:
            if not _is_missing_log_stream_error(exc):
                raise
            last_error = exc
            messages = []
        else:
            try:
                return messages, _extract_json_payload(messages)
            except Exception as exc:
                last_error = exc
        now = time.time()
        if now >= deadline:
            break
        time.sleep(min(DEFAULT_LOG_POLL_SECONDS, max(1, int(deadline - now))))
    raise RuntimeError(
        f"graph command {' '.join(command)} did not emit valid JSON for {task_arn}: {last_error}; "
        f"log tail: {_log_tail(messages)}"
    ) from last_error


def _run_graph_command(
    resource_prefix: str,
    service: dict[str, Any],
    command: list[str],
    timeout_seconds: int,
    poll_seconds: int,
    region: str,
    context: GraphCommandContext | None = None,
    allow_nonzero: bool = False,
) -> GraphCommandResult:
    context = context or _graph_command_context(resource_prefix, service, region)
    overrides = _graph_command_overrides_from_names(
        command,
        {"source-runtime-bootstrap"} if context.has_source_runtime_bootstrap else set(),
    )
    task_definition = context.task_definition
    temporary_task_definition = None
    if context.has_source_runtime_bootstrap:
        payload = context.task_definition_without_bootstrap
        if payload is None:
            payload = _task_definition_without_bootstrap(context.task_definition, region)
        if payload is not None:
            temporary_task_definition = _register_graph_command_task_definition(payload, region)
            task_definition = temporary_task_definition
    try:
        response = _aws(
            [
                "ecs",
                "run-task",
                "--cluster",
                context.cluster,
                "--task-definition",
                task_definition,
                "--launch-type",
                "FARGATE",
                "--network-configuration",
                json.dumps(context.network_configuration, separators=(",", ":")),
                "--overrides",
                json.dumps(overrides, separators=(",", ":")),
            ],
            region,
        )
    finally:
        if temporary_task_definition is not None:
            _deregister_graph_command_task_definition(temporary_task_definition, region)
    failures = response.get("failures") or []
    if failures:
        raise RuntimeError(f"failed to start graph command {' '.join(command)}: {failures}")
    tasks = response.get("tasks") or []
    if len(tasks) != 1:
        raise RuntimeError(f"expected one task for graph command {' '.join(command)}, got {len(tasks)}")
    task_arn = tasks[0]["taskArn"]
    _wait_for_task(context.cluster, task_arn, timeout_seconds, poll_seconds, region)
    task = _describe_tasks(context.cluster, [task_arn], region)[0]
    containers = task.get("containers") or []
    cerebro_container = next((container for container in containers if container.get("name") == "cerebro"), None)
    exit_code = cerebro_container.get("exitCode") if cerebro_container else None
    def fetch_messages() -> list[str]:
        return _task_messages(task, region, (context.log_group, context.stream_prefix))

    if exit_code != 0 and not allow_nonzero:
        try:
            messages = _wait_for_task_messages(fetch_messages)
        except Exception as exc:
            raise RuntimeError(
                f"graph command {' '.join(command)} exited with {exit_code}: {task_arn}; "
                f"unable to fetch task logs: {exc}; ECS task stop: {_task_stop_summary(task)}"
            ) from exc
        raise RuntimeError(f"graph command {' '.join(command)} exited with {exit_code}: {task_arn}; log tail: {_log_tail(messages)}")
    try:
        messages, payload = _extract_graph_payload_with_retries(command, task_arn, fetch_messages)
    except Exception as exc:
        raise RuntimeError(
            f"graph command {' '.join(command)} failed for {task_arn}; "
            f"ECS task stop: {_task_stop_summary(task)}; {exc}"
        ) from exc
    return GraphCommandResult(command=command, task_arn=task_arn, exit_code=exit_code, payload=payload)


def _run_graph_command_with_retries(
    resource_prefix: str,
    service: dict[str, Any],
    command: list[str],
    timeout_seconds: int,
    poll_seconds: int,
    region: str,
    retry_seconds: int,
    context: GraphCommandContext | None = None,
    overall_deadline: float | None = None,
    allow_nonzero: bool = False,
) -> GraphCommandResult:
    retry_deadline = time.time() + retry_seconds
    if overall_deadline is not None:
        retry_deadline = min(retry_deadline, overall_deadline)
    while True:
        try:
            attempt_timeout_seconds = _credential_safe_timeout(overall_deadline, timeout_seconds)
            return _run_graph_command(
                resource_prefix,
                service,
                command,
                attempt_timeout_seconds,
                poll_seconds,
                region,
                context,
                allow_nonzero=allow_nonzero,
            )
        except Exception as exc:
            now = time.time()
            if retry_seconds <= 0 or now >= retry_deadline:
                raise
            detail = _truncate_detail(str(exc), INGEST_RUN_ERROR_DETAIL_LIMIT)
            print(f"WARNING: graph command {' '.join(command)} failed: {detail}; retrying", file=sys.stderr)
            time.sleep(min(poll_seconds, max(1, int(retry_deadline - now))))


def _verify_counts(payload: dict[str, Any]) -> None:
    errors = _count_health_errors(payload)
    if errors:
        raise RuntimeError("; ".join(errors))


def _count_health_errors(payload: dict[str, Any]) -> list[str]:
    nodes = int(payload.get("nodes") or 0)
    relations = int(payload.get("relations") or 0)
    errors: list[str] = []
    if nodes <= 0:
        errors.append(f"graph node count must be positive, got {nodes}")
    if relations <= 0:
        errors.append(f"graph relation count must be positive, got {relations}")
    return errors


def _verify_integrity(payload: dict[str, Any]) -> None:
    failed = int(payload.get("failed") or 0)
    if failed != 0:
        failed_checks = _failed_integrity_checks(payload)
        raise RuntimeError(f"graph integrity failed {failed} checks: {', '.join(failed_checks)}")


def _failed_integrity_checks(payload: dict[str, Any]) -> list[str]:
    checks = payload.get("checks") or []
    return [
        f"{check.get('name')}={check.get('actual')}"
        for check in checks
        if isinstance(check, dict) and not bool(check.get("passed"))
    ]


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _verify_current_ingest_runs(
    payload: dict[str, Any],
    declared_runtime_ids: set[str] | None = None,
    max_running_minutes: int = DEFAULT_MAX_RUNNING_MINUTES,
    allow_transient_source_failures: bool = False,
    now: datetime | None = None,
) -> int:
    latest_by_runtime = _latest_ingest_runs_by_runtime(payload)
    declared_runtime_ids = declared_runtime_ids or set()
    missing = sorted(declared_runtime_ids - set(latest_by_runtime))
    if missing:
        raise CurrentIngestRunsError(
            f"missing graph ingest run history for {len(missing)} declared runtime(s): {', '.join(missing)}",
            retryable=False,
        )
    successful_runtime_ids = _successful_ingest_runtime_ids(payload)
    failed = [
        run
        for run in latest_by_runtime.values()
        if str(run.get("status") or "").strip() == "failed"
        and not _can_ignore_transient_source_failure(run, successful_runtime_ids, allow_transient_source_failures)
    ]
    if failed:
        summary = ", ".join(_ingest_run_summary(run) for run in failed)
        raise CurrentIngestRunsError(f"latest graph ingest run failed for {len(failed)} runtime(s): {summary}", retryable=True)
    running = [run for run in latest_by_runtime.values() if str(run.get("status") or "").strip() == "running"]
    now = now or datetime.now(UTC)
    stale_running = []
    for run in running:
        started_at = _parse_time(run.get("started_at"))
        if started_at is not None and (now - started_at).total_seconds() > max_running_minutes * 60:
            stale_running.append(run)
    if stale_running:
        summary = ", ".join(_ingest_run_summary(run) for run in stale_running)
        raise CurrentIngestRunsError(f"latest graph ingest run is stale-running for {len(stale_running)} runtime(s): {summary}", retryable=True)
    zero_projection = [
        run
        for run in latest_by_runtime.values()
        if str(run.get("status") or "").strip() == "completed"
        and int(run.get("events_read") or 0) > 0
        and int(run.get("entities_projected") or 0) == 0
        and int(run.get("links_projected") or 0) == 0
    ]
    if zero_projection:
        summary = ", ".join(_ingest_run_summary(run) for run in zero_projection)
        raise CurrentIngestRunsError(f"latest graph ingest projected no graph records for {len(zero_projection)} runtime(s): {summary}", retryable=True)
    return len(latest_by_runtime)


def _successful_ingest_runtime_ids(payload: dict[str, Any]) -> set[str]:
    runtime_ids: set[str] = set()
    for run in payload.get("runs") or []:
        if not isinstance(run, dict):
            continue
        if str(run.get("status") or "").strip() != "completed":
            continue
        runtime_id = str(run.get("runtime_id") or run.get("id") or "").strip()
        if runtime_id:
            runtime_ids.add(runtime_id)
    return runtime_ids


def _can_ignore_transient_source_failure(run: dict[str, Any], successful_runtime_ids: set[str], enabled: bool) -> bool:
    if not enabled:
        return False
    runtime_id = str(run.get("runtime_id") or run.get("id") or "").strip()
    if runtime_id not in successful_runtime_ids:
        return False
    error = str(run.get("error") or "").lower()
    return any(
        token in error
        for token in (
            "client.timeout exceeded",
            "context deadline exceeded",
            "i/o timeout",
            "request canceled",
            "temporary failure",
            "tls handshake timeout",
        )
    )


def _ingest_run_summary(run: dict[str, Any]) -> str:
    runtime_id = str(run.get("runtime_id") or "").strip()
    run_id = str(run.get("id") or "").strip()
    summary = f"{runtime_id}:{run_id}" if runtime_id or run_id else "<unknown-runtime>"
    for key in ("status", "started_at", "finished_at", "events_read", "entities_projected", "links_projected"):
        value = run.get(key)
        if value is not None and str(value).strip() != "":
            summary = f"{summary}:{key}={value}"
    error = str(run.get("error") or "").strip()
    if error:
        summary = f"{summary}:error={_truncate_detail(error, INGEST_RUN_ERROR_DETAIL_LIMIT)}"
    return summary


def _truncate_detail(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: max(0, limit - 3)]}..."


def _verify_current_ingest_runs_with_retries(
    resource_prefix: str,
    service: dict[str, Any],
    declared_runtime_ids: set[str],
    wait_timeout_seconds: int,
    poll_seconds: int,
    region: str,
    graph_command_retry_seconds: int,
    ingest_health_retry_seconds: int,
    max_running_minutes: int,
    allow_transient_source_failures: bool,
    context: GraphCommandContext | None = None,
    overall_deadline: float | None = None,
) -> tuple[GraphCommandResult, int]:
    deadline = time.time() + ingest_health_retry_seconds
    if overall_deadline is not None:
        deadline = min(deadline, overall_deadline)
    while True:
        ingest_runs = _run_graph_command_with_retries(
            resource_prefix,
            service,
            ["graph", "ingest-runs", f"limit={_ingest_run_limit(declared_runtime_ids)}"],
            wait_timeout_seconds,
            poll_seconds,
            region,
            graph_command_retry_seconds,
            context,
            overall_deadline=overall_deadline,
        )
        try:
            current_ingest_runtimes = _verify_current_ingest_runs(
                ingest_runs.payload,
                declared_runtime_ids=declared_runtime_ids,
                max_running_minutes=max_running_minutes,
                allow_transient_source_failures=allow_transient_source_failures,
            )
            return ingest_runs, current_ingest_runtimes
        except CurrentIngestRunsError as exc:
            now = time.time()
            if ingest_health_retry_seconds <= 0 or not exc.retryable or now >= deadline:
                raise
            print(f"WARNING: {exc}; retrying graph ingest health", file=sys.stderr)
            time.sleep(min(poll_seconds, max(1, int(deadline - now))))


def _graph_health_command(
    declared_runtime_ids: set[str],
    required_relations: set[str],
    max_running_minutes: int,
    allow_transient_source_failures: bool,
) -> list[str]:
    command = [
        "graph",
        "health",
        f"limit={_ingest_run_limit(declared_runtime_ids)}",
        f"max_running_minutes={max_running_minutes}",
    ]
    if required_relations:
        command.append(f"relations={','.join(sorted(required_relations))}")
    if allow_transient_source_failures:
        command.append("allow_transient_source_failures=true")
    if declared_runtime_ids:
        runtime_ids_arg = f"runtime_ids={','.join(sorted(declared_runtime_ids))}"
        if _ecs_container_overrides_size([*command, runtime_ids_arg]) <= MAX_ECS_CONTAINER_OVERRIDES_BYTES:
            command.append(runtime_ids_arg)
    return command


def _ecs_container_overrides_size(command: list[str]) -> int:
    return len(json.dumps(_graph_command_overrides_from_names(command, {"cerebro"}), separators=(",", ":")).encode("utf-8"))


def _graph_health_command_has_runtime_ids(command: list[str]) -> bool:
    return any(argument.startswith("runtime_ids=") for argument in command)


def _graph_health_payload_with_failure(payload: dict[str, Any], failure: str) -> dict[str, Any]:
    updated = dict(payload)
    failures = updated.get("failures") or []
    if not isinstance(failures, list):
        failures = [failures]
    updated["failures"] = [str(item).strip() for item in failures if str(item).strip()]
    updated["failures"].append(failure)
    return updated


def _graph_health_errors(payload: dict[str, Any], exit_code: int | None) -> list[str]:
    failures = payload.get("failures") or []
    if not isinstance(failures, list):
        failures = [failures]
    errors = [str(failure).strip() for failure in failures if str(failure).strip()]
    status = str(payload.get("status") or "").strip()
    if status and status != "passed" and not errors:
        errors.append(f"graph health status is {status}")
    if exit_code not in (0, None) and not errors:
        errors.append(f"graph health command exited with {exit_code}")
    return errors


def _run_graph_health_command_with_retries(
    resource_prefix: str,
    service: dict[str, Any],
    declared_runtime_ids: set[str],
    required_relations: set[str],
    wait_timeout_seconds: int,
    poll_seconds: int,
    region: str,
    graph_command_retry_seconds: int,
    ingest_health_retry_seconds: int,
    max_running_minutes: int,
    allow_transient_source_failures: bool,
    context: GraphCommandContext | None = None,
    overall_deadline: float | None = None,
) -> GraphCommandResult:
    command = _graph_health_command(
        declared_runtime_ids,
        required_relations,
        max_running_minutes,
        allow_transient_source_failures,
    )
    runtime_ids_in_command = _graph_health_command_has_runtime_ids(command)
    deadline = time.time() + ingest_health_retry_seconds
    if overall_deadline is not None:
        deadline = min(deadline, overall_deadline)
    while True:
        nonretryable_error = False
        result = _run_graph_command_with_retries(
            resource_prefix,
            service,
            command,
            wait_timeout_seconds,
            poll_seconds,
            region,
            graph_command_retry_seconds,
            context,
            overall_deadline=overall_deadline,
            allow_nonzero=True,
        )
        errors = _graph_health_errors(result.payload, result.exit_code)
        if not errors and declared_runtime_ids and not runtime_ids_in_command:
            try:
                _verify_current_ingest_runs_with_retries(
                    resource_prefix,
                    service,
                    declared_runtime_ids,
                    wait_timeout_seconds,
                    poll_seconds,
                    region,
                    graph_command_retry_seconds,
                    ingest_health_retry_seconds,
                    max_running_minutes,
                    allow_transient_source_failures,
                    context,
                    overall_deadline=overall_deadline,
                )
            except CurrentIngestRunsError as exc:
                nonretryable_error = not exc.retryable
                result = GraphCommandResult(
                    command=result.command,
                    task_arn=result.task_arn,
                    exit_code=result.exit_code or 1,
                    payload=_graph_health_payload_with_failure(result.payload, str(exc)),
                )
                errors = _graph_health_errors(result.payload, result.exit_code)
        now = time.time()
        if not errors or nonretryable_error or ingest_health_retry_seconds <= 0 or now >= deadline:
            return result
        print(
            f"WARNING: graph health command reported {len(errors)} failure(s): "
            f"{_truncate_detail('; '.join(errors), INGEST_RUN_ERROR_DETAIL_LIMIT)}; retrying",
            file=sys.stderr,
        )
        time.sleep(min(poll_seconds, max(1, int(deadline - now))))


def _graph_health_counts(payload: dict[str, Any]) -> dict[str, Any]:
    counts = payload.get("counts") or {}
    if not isinstance(counts, dict):
        raise ValueError("graph health payload must include a counts object")
    return counts


def _graph_health_integrity(payload: dict[str, Any]) -> dict[str, Any]:
    integrity = payload.get("integrity") or {}
    if not isinstance(integrity, dict):
        raise ValueError("graph health payload must include an integrity object")
    return integrity


def _graph_health_relation_counts(payload: dict[str, Any]) -> dict[str, int]:
    counts = payload.get("relation_counts") or {}
    if not isinstance(counts, dict):
        raise ValueError("graph health payload relation_counts must be an object")
    return {str(relation): int(count or 0) for relation, count in counts.items()}


def _graph_health_current_ingest_runtimes(payload: dict[str, Any]) -> int:
    ingest = payload.get("ingest") or {}
    if not isinstance(ingest, dict):
        raise ValueError("graph health payload must include an ingest object")
    return int(ingest.get("current_runtime_count") or 0)


def _graph_health_missing_ingest_runtimes(payload: dict[str, Any]) -> list[str]:
    ingest = payload.get("ingest") or {}
    if not isinstance(ingest, dict):
        return []
    missing = ingest.get("missing_runtime_ids") or []
    if not isinstance(missing, list):
        return []
    return sorted(str(runtime_id).strip() for runtime_id in missing if str(runtime_id).strip())


def _latest_ingest_runs_by_runtime(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    runs = payload.get("runs") or []
    if not isinstance(runs, list):
        raise ValueError("graph ingest-runs payload must include a runs list")
    latest_by_runtime: dict[str, dict[str, Any]] = {}
    for run in runs:
        if not isinstance(run, dict):
            continue
        runtime_id = str(run.get("runtime_id") or run.get("id") or "").strip()
        if runtime_id and runtime_id not in latest_by_runtime:
            latest_by_runtime[runtime_id] = run
    return latest_by_runtime


def _missing_declared_ingest_runtime_ids(payload: dict[str, Any], declared_runtime_ids: set[str]) -> list[str]:
    return sorted(declared_runtime_ids - set(_latest_ingest_runs_by_runtime(payload)))


def _graph_path_relations(payload: dict[str, Any]) -> set[str]:
    relations: set[str] = set()
    for pattern in payload.get("patterns") or []:
        if not isinstance(pattern, dict):
            continue
        for key in ("first_relation", "second_relation"):
            value = str(pattern.get(key) or "").strip()
            if value:
                relations.add(value)
    for traversal in payload.get("traversals") or []:
        if not isinstance(traversal, dict):
            continue
        for key in ("first_relation", "second_relation"):
            value = str(traversal.get(key) or "").strip()
            if value:
                relations.add(value)
    return relations


def _required_graph_relations(
    aws_families: set[str] | None = None,
    attack_path_relations_supported: bool = True,
) -> set[str]:
    required = set(REQUIRED_RELATIONS)
    aws_families = aws_families or set()
    if attack_path_relations_supported:
        if aws_families & AWS_CAN_REACH_REQUIRED_FAMILIES:
            required.add("can_reach")
        if aws_families & AWS_CAN_ASSUME_REQUIRED_FAMILIES:
            required.add("can_assume")
        if aws_families & AWS_CAN_PERFORM_REQUIRED_FAMILIES:
            required.add("can_perform")
    return required


def _verify_required_graph_relations(
    payload: dict[str, Any],
    aws_families: set[str] | None = None,
    attack_path_relations_supported: bool = True,
) -> set[str]:
    relations = _graph_path_relations(payload)
    required = _required_graph_relations(aws_families, attack_path_relations_supported)
    missing = sorted(required - relations)
    if missing:
        raise RuntimeError(f"graph paths missing required relation(s): {', '.join(missing)}")
    return relations


def _graph_relation_counts(payload: dict[str, Any]) -> dict[str, int]:
    counts = payload.get("relations") or {}
    if not isinstance(counts, dict):
        raise ValueError("graph relation-counts payload must include a relations object")
    return {str(relation): int(count or 0) for relation, count in counts.items()}


def _verify_required_graph_relation_counts(
    payload: dict[str, Any],
    aws_families: set[str] | None = None,
    attack_path_relations_supported: bool = True,
) -> set[str]:
    counts = _graph_relation_counts(payload)
    missing = _missing_required_graph_relation_counts(
        counts,
        aws_families,
        attack_path_relations_supported=attack_path_relations_supported,
    )
    if missing:
        raise RuntimeError(f"graph relation counts missing required relation(s): {', '.join(missing)}")
    return {relation for relation, count in counts.items() if count > 0}


def _missing_required_graph_relation_counts(
    relation_counts: dict[str, int],
    aws_families: set[str] | None = None,
    attack_path_relations_supported: bool = True,
) -> list[str]:
    required = _required_graph_relations(aws_families, attack_path_relations_supported)
    return sorted(relation for relation in required if relation_counts.get(relation, 0) <= 0)


def _markdown_escape(value: str) -> str:
    return value.replace("|", "\\|")


def _summary_markdown(
    stack: str,
    counts_payload: dict[str, Any],
    integrity_payload: dict[str, Any],
    relation_counts: dict[str, int],
    graph_relations: set[str],
    current_ingest_runtimes: int,
    declared_runtime_count: int,
    graph_health_errors: list[str],
    failed_integrity_checks: list[str],
    missing_ingest_runtimes: list[str],
    missing_graph_relations: list[str],
    aws_families: set[str],
) -> str:
    failed_checks = int(integrity_payload.get("failed") or 0)
    status = "failed" if graph_health_errors or failed_checks or missing_ingest_runtimes or missing_graph_relations else "passed"
    lines = [
        f"## Graph Health: `{stack}`",
        "",
        f"Status: **{status}**",
        f"Nodes: `{counts_payload.get('nodes')}`",
        f"Relationships: `{counts_payload.get('relations')}`",
        f"Integrity checks: `{integrity_payload.get('passed', 0)} passed / {failed_checks} failed`",
        f"Current ingest runtimes: `{current_ingest_runtimes}` / `{declared_runtime_count}`",
        f"AWS source families: `{', '.join(sorted(aws_families)) if aws_families else 'none'}`",
        f"Observed relation families: `{', '.join(sorted(graph_relations)) if graph_relations else 'none'}`",
        "",
    ]
    if graph_health_errors:
        lines.extend(
            [
                "| Graph health failure |",
                "| --- |",
            ]
        )
        for error in graph_health_errors:
            lines.append(f"| `{_markdown_escape(error)}` |")
        lines.append("")
    if failed_integrity_checks:
        lines.extend(
            [
                "| Failed integrity check |",
                "| --- |",
            ]
        )
        for check in failed_integrity_checks:
            lines.append(f"| `{_markdown_escape(check)}` |")
        lines.append("")
    if missing_ingest_runtimes:
        lines.extend(
            [
                "| Missing ingest runtime |",
                "| --- |",
            ]
        )
        for runtime_id in missing_ingest_runtimes:
            lines.append(f"| `{_markdown_escape(runtime_id)}` |")
        lines.append("")
    if missing_graph_relations:
        lines.extend(
            [
                "| Missing graph relation |",
                "| --- |",
            ]
        )
        for relation in missing_graph_relations:
            lines.append(f"| `{_markdown_escape(relation)}` |")
        lines.append("")
    if relation_counts:
        lines.extend(
            [
                "| Relation | Count |",
                "| --- | ---: |",
            ]
        )
        for relation, count in sorted(relation_counts.items()):
            lines.append(f"| `{_markdown_escape(relation)}` | {count} |")
        lines.append("")
    return "\n".join(lines)


def _write_github_summary(
    stack: str,
    counts_payload: dict[str, Any],
    integrity_payload: dict[str, Any],
    relation_counts: dict[str, int],
    graph_relations: set[str],
    current_ingest_runtimes: int,
    declared_runtime_count: int,
    graph_health_errors: list[str],
    failed_integrity_checks: list[str],
    missing_ingest_runtimes: list[str],
    missing_graph_relations: list[str],
    aws_families: set[str],
) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write(
            _summary_markdown(
                stack,
                counts_payload,
                integrity_payload,
                relation_counts,
                graph_relations,
                current_ingest_runtimes,
                declared_runtime_count,
                graph_health_errors,
                failed_integrity_checks,
                missing_ingest_runtimes,
                missing_graph_relations,
                aws_families,
            )
        )


def _is_graph_paths_timeout(exc: Exception) -> bool:
    return "context deadline exceeded" in str(exc).lower()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify live Cerebro graph health through a one-off ECS task.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--wait-timeout-seconds", type=int, default=DEFAULT_WAIT_TIMEOUT_SECONDS)
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--max-running-minutes", type=int, default=DEFAULT_MAX_RUNNING_MINUTES)
    parser.add_argument("--graph-command-retry-seconds", type=int, default=DEFAULT_GRAPH_COMMAND_RETRY_SECONDS)
    parser.add_argument("--ingest-health-retry-seconds", type=int, default=1800)
    parser.add_argument("--credential-safe-timeout-seconds", type=int, default=DEFAULT_CREDENTIAL_SAFE_TIMEOUT_SECONDS)
    parser.add_argument(
        "--require-bundled-health",
        action="store_true",
        help="Fail instead of falling back to multi-task graph checks when the image lacks the bundled graph health command.",
    )
    parser.add_argument("--graph-command", nargs=argparse.REMAINDER, help="Run one graph command through ECS and print its JSON payload.")
    parser.add_argument(
        "--allow-transient-source-failures",
        action="store_true",
        help="Do not fail deployment health when the latest source ingest failed due to a transient provider timeout and older successful graph ingest history exists.",
    )
    args = parser.parse_args(argv)
    overall_deadline = None
    if args.credential_safe_timeout_seconds > 0:
        overall_deadline = time.time() + args.credential_safe_timeout_seconds

    stack = _stack_name(args.stack_file)
    config = _load_config(args.stack_file)
    _verify_account(stack, args.region)
    resource_prefix = _resource_prefix(config, stack)
    service = _describe_api_service(resource_prefix, args.region)
    graph_command_context = _graph_command_context(resource_prefix, service, args.region)
    declared_runtime_ids = _declared_runtime_ids(config)
    aws_families = _declared_aws_families(config)
    attack_path_relations_supported = _supports_attack_path_relations(config)

    if args.graph_command is not None:
        if not args.graph_command:
            raise RuntimeError("--graph-command requires at least one command argument")
        result = _run_graph_command_with_retries(
            resource_prefix,
            service,
            args.graph_command,
            args.wait_timeout_seconds,
            args.poll_seconds,
            args.region,
            args.graph_command_retry_seconds,
            graph_command_context,
            overall_deadline=overall_deadline,
        )
        print(json.dumps(result.payload, sort_keys=True))
        return 0

    def run_graph_command(command: list[str]) -> GraphCommandResult:
        return _run_graph_command_with_retries(
            resource_prefix,
            service,
            command,
            args.wait_timeout_seconds,
            args.poll_seconds,
            args.region,
            args.graph_command_retry_seconds,
            graph_command_context,
            overall_deadline=overall_deadline,
        )

    graph_relations: set[str] = set()
    relation_counts_payload: dict[str, int] = {}
    missing_graph_relations: list[str] = []
    supports_relation_counts = _supports_relation_counts(config)
    required_relations = _required_graph_relations(
        aws_families,
        attack_path_relations_supported=attack_path_relations_supported,
    )

    supports_graph_health_command = _supports_graph_health_command(config)
    if args.require_bundled_health and not supports_graph_health_command:
        raise RuntimeError("stack image does not support bundled graph health command")

    if supports_graph_health_command:
        graph_health = _run_graph_health_command_with_retries(
            resource_prefix,
            service,
            declared_runtime_ids,
            required_relations,
            args.wait_timeout_seconds,
            args.poll_seconds,
            args.region,
            args.graph_command_retry_seconds,
            args.ingest_health_retry_seconds,
            args.max_running_minutes,
            args.allow_transient_source_failures,
            graph_command_context,
            overall_deadline=overall_deadline,
        )
        counts_payload = _graph_health_counts(graph_health.payload)
        integrity_payload = _graph_health_integrity(graph_health.payload)
        relation_counts_payload = _graph_health_relation_counts(graph_health.payload)
        missing_graph_relations = _missing_required_graph_relation_counts(
            relation_counts_payload,
            aws_families,
            attack_path_relations_supported=attack_path_relations_supported,
        )
        graph_relations = {relation for relation, count in relation_counts_payload.items() if count > 0}
        current_ingest_runtimes = _graph_health_current_ingest_runtimes(graph_health.payload)
        missing_ingest_runtimes = _graph_health_missing_ingest_runtimes(graph_health.payload)
        graph_health_errors = _graph_health_errors(graph_health.payload, graph_health.exit_code)
        failed_integrity_checks = _failed_integrity_checks(integrity_payload)
        counts_task_arn = graph_health.task_arn
        integrity_task_arn = graph_health.task_arn
        paths_task_arn = graph_health.task_arn
        ingest_runs_task_arn = graph_health.task_arn
    else:
        paths_task_arn = ""
        with ThreadPoolExecutor(max_workers=4) as executor:
            counts_future = executor.submit(run_graph_command, ["graph", "counts"])
            integrity_future = executor.submit(run_graph_command, ["graph", "integrity"])
            ingest_runs_future = executor.submit(
                _verify_current_ingest_runs_with_retries,
                resource_prefix,
                service,
                declared_runtime_ids,
                args.wait_timeout_seconds,
                args.poll_seconds,
                args.region,
                args.graph_command_retry_seconds,
                args.ingest_health_retry_seconds,
                args.max_running_minutes,
                args.allow_transient_source_failures,
                graph_command_context,
                overall_deadline=overall_deadline,
            )
            if supports_relation_counts:
                relation_future = executor.submit(
                    run_graph_command,
                    ["graph", "relation-counts", f"relations={','.join(sorted(required_relations | GRAPH_RELATIONS_TO_OBSERVE))}"],
                )
                paths_future = None
            else:
                relation_future = None
                paths_future = executor.submit(
                    run_graph_command,
                    ["graph", "paths", "limit=100"],
                )

            counts = counts_future.result()
            counts_payload = counts.payload
            counts_task_arn = counts.task_arn
            graph_health_errors = _count_health_errors(counts_payload)
            integrity = integrity_future.result()
            integrity_payload = integrity.payload
            integrity_task_arn = integrity.task_arn
            failed_integrity_checks = _failed_integrity_checks(integrity_payload)
            if relation_future is not None:
                relation_counts = relation_future.result()
                paths_task_arn = relation_counts.task_arn
                relation_counts_payload = _graph_relation_counts(relation_counts.payload)
                missing_graph_relations = _missing_required_graph_relation_counts(
                    relation_counts_payload,
                    aws_families,
                    attack_path_relations_supported=attack_path_relations_supported,
                )
                graph_relations = {relation for relation, count in relation_counts_payload.items() if count > 0}
            elif paths_future is not None:
                try:
                    paths = paths_future.result()
                except Exception as exc:
                    if not _is_graph_paths_timeout(exc):
                        raise
                    print(f"WARNING: skipping graph path relation assertions after timeout: {exc}", file=sys.stderr)
                else:
                    paths_task_arn = paths.task_arn
                    graph_relations = _verify_required_graph_relations(
                        paths.payload,
                        aws_families,
                        attack_path_relations_supported=attack_path_relations_supported,
                    )
            ingest_runs, current_ingest_runtimes = ingest_runs_future.result()
            ingest_runs_task_arn = ingest_runs.task_arn

        missing_ingest_runtimes = _missing_declared_ingest_runtime_ids(ingest_runs.payload, declared_runtime_ids)
    if missing_ingest_runtimes:
        print(
            f"WARNING: missing graph ingest run history for declared runtime(s): {', '.join(missing_ingest_runtimes)}",
            file=sys.stderr,
        )

    _write_github_summary(
        stack,
        counts_payload,
        integrity_payload,
        relation_counts_payload,
        graph_relations,
        current_ingest_runtimes,
        len(declared_runtime_ids),
        graph_health_errors,
        failed_integrity_checks,
        missing_ingest_runtimes,
        missing_graph_relations,
        aws_families,
    )

    failures = [*graph_health_errors]
    if failed_integrity_checks:
        failures.append(f"graph integrity failed {int(integrity_payload.get('failed') or 0)} checks: {', '.join(failed_integrity_checks)}")
    if failures:
        raise RuntimeError("; ".join(failures))
    if missing_graph_relations:
        raise RuntimeError(f"graph relation counts missing required relation(s): {', '.join(missing_graph_relations)}")

    print("checked_at\tstack\tnodes\trelations\tintegrity_passed\tintegrity_failed\tgraph_relations\tcurrent_ingest_runtimes\tdeclared_runtimes\tmissing_ingest_runtimes\tcounts_task\tintegrity_task\tpaths_task\tingest_runs_task")
    print(
        "\t".join(
            [
                datetime.now(UTC).isoformat(),
                stack,
                str(counts_payload.get("nodes")),
                str(counts_payload.get("relations")),
                str(integrity_payload.get("passed")),
                str(integrity_payload.get("failed")),
                ",".join(sorted(graph_relations)),
                str(current_ingest_runtimes),
                str(len(declared_runtime_ids)),
                ",".join(missing_ingest_runtimes),
                counts_task_arn,
                integrity_task_arn,
                paths_task_arn,
                ingest_runs_task_arn,
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
