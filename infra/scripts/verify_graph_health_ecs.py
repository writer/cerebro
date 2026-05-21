#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any

import yaml


EXPECTED_STACK_ACCOUNTS = {
    "sec-dev": "944130631940",
    "go-prod": "837279440628",
}
DEFAULT_MAX_RUNNING_MINUTES = 60
MIN_INGEST_RUN_LIMIT = 100
INGEST_RUN_LIMIT_MULTIPLIER = 20
MAX_INGEST_RUN_LIMIT = 500
ATTACK_PATH_RELATION_MIN_TAG = (2, 1, 46)
RELATION_COUNT_MIN_TAG = (2, 1, 50)
REQUIRED_RELATIONS = {"belongs_to", "represents"}
AWS_CAN_REACH_REQUIRED_FAMILIES = {"resource_exposure"}
AWS_ATTACK_PATH_RELATIONS = {"can_perform", "can_assume", "can_admin", "can_impersonate"}


@dataclass(frozen=True)
class GraphCommandResult:
    command: list[str]
    task_arn: str
    exit_code: int | None
    payload: dict[str, Any]


def _stack_name(path: Path) -> str:
    name = path.name
    if name.startswith("Pulumi.") and name.endswith(".yaml"):
        return name.removeprefix("Pulumi.").removesuffix(".yaml")
    return path.stem


def _load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    config = loaded.get("config")
    if not isinstance(config, dict):
        raise ValueError(f"{path} must contain a top-level config mapping")
    return {
        key.removeprefix("cerebro:"): value
        for key, value in config.items()
        if isinstance(key, str) and key.startswith("cerebro:")
    }


def _resource_prefix(config: dict[str, Any], stack: str) -> str:
    environment = str(config.get("environment") or stack).strip()
    if not environment:
        raise ValueError("cerebro:environment is required")
    return f"cerebro-{environment}"


def _declared_runtime_ids(config: dict[str, Any]) -> set[str]:
    runtimes = config.get("sourceRuntimes") or []
    if not isinstance(runtimes, list):
        return set()
    return {str(runtime.get("id") or "").strip() for runtime in runtimes if isinstance(runtime, dict) and str(runtime.get("id") or "").strip()}


def _declared_aws_families(config: dict[str, Any]) -> set[str]:
    runtimes = config.get("sourceRuntimes") or []
    if not isinstance(runtimes, list):
        return set()
    families: set[str] = set()
    for runtime in runtimes:
        if not isinstance(runtime, dict) or str(runtime.get("sourceId", "")).strip() != "aws":
            continue
        runtime_config = runtime.get("config") or {}
        if isinstance(runtime_config, dict):
            family = str(runtime_config.get("family", "")).strip()
            if family:
                families.add(family)
    return families


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


def _graph_command_overrides(task_definition: str, command: list[str], region: str) -> dict[str, Any]:
    container_overrides = [{"name": "cerebro", "command": command}]
    if "source-runtime-bootstrap" in _task_definition_container_names(task_definition, region):
        container_overrides.append({"name": "source-runtime-bootstrap", "command": ["graph", "counts"]})
    return {"containerOverrides": container_overrides}


def _wait_for_task(cluster: str, task_arn: str, timeout_seconds: int, poll_seconds: int, region: str) -> None:
    deadline = time.time() + timeout_seconds
    while True:
        tasks = _describe_tasks(cluster, [task_arn], region)
        if tasks and tasks[0].get("lastStatus") == "STOPPED":
            return
        if time.time() >= deadline:
            break
        time.sleep(min(poll_seconds, max(1, int(deadline - time.time()))))
    raise TimeoutError(f"task {task_arn} did not stop within {timeout_seconds} seconds")


def _log_options(task_definition: str, region: str) -> tuple[str, str]:
    response = _aws(["ecs", "describe-task-definition", "--task-definition", task_definition], region)
    containers = response["taskDefinition"]["containerDefinitions"]
    container = next(item for item in containers if item.get("name") == "cerebro")
    options = container["logConfiguration"]["options"]
    return options["awslogs-group"], options["awslogs-stream-prefix"]


def _task_messages(task: dict[str, Any], region: str) -> list[str]:
    log_group, stream_prefix = _log_options(task["taskDefinitionArn"], region)
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


def _extract_json_payload(messages: list[str]) -> dict[str, Any]:
    text = "\n".join(message for message in messages if message.strip())
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise ValueError(f"graph command did not emit a JSON object: {text[-500:]}")
    payload = json.loads(text[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("graph command JSON payload must be an object")
    return payload


def _run_graph_command(
    resource_prefix: str,
    service: dict[str, Any],
    command: list[str],
    timeout_seconds: int,
    poll_seconds: int,
    region: str,
) -> GraphCommandResult:
    cluster = f"{resource_prefix}-cluster"
    task_definition = _latest_active_task_definition(service["taskDefinition"], region)
    overrides = _graph_command_overrides(task_definition, command, region)
    response = _aws(
        [
            "ecs",
            "run-task",
            "--cluster",
            cluster,
            "--task-definition",
            task_definition,
            "--launch-type",
            "FARGATE",
            "--network-configuration",
            json.dumps(_network_configuration(service), separators=(",", ":")),
            "--overrides",
            json.dumps(overrides, separators=(",", ":")),
        ],
        region,
    )
    failures = response.get("failures") or []
    if failures:
        raise RuntimeError(f"failed to start graph command {' '.join(command)}: {failures}")
    tasks = response.get("tasks") or []
    if len(tasks) != 1:
        raise RuntimeError(f"expected one task for graph command {' '.join(command)}, got {len(tasks)}")
    task_arn = tasks[0]["taskArn"]
    _wait_for_task(cluster, task_arn, timeout_seconds, poll_seconds, region)
    task = _describe_tasks(cluster, [task_arn], region)[0]
    containers = task.get("containers") or []
    cerebro_container = next((container for container in containers if container.get("name") == "cerebro"), None)
    exit_code = cerebro_container.get("exitCode") if cerebro_container else None
    messages = _task_messages(task, region)
    payload = _extract_json_payload(messages)
    if exit_code != 0:
        raise RuntimeError(f"graph command {' '.join(command)} exited with {exit_code}: {task_arn}")
    return GraphCommandResult(command=command, task_arn=task_arn, exit_code=exit_code, payload=payload)


def _verify_counts(payload: dict[str, Any]) -> None:
    nodes = int(payload.get("nodes") or 0)
    relations = int(payload.get("relations") or 0)
    if nodes <= 0:
        raise RuntimeError(f"graph node count must be positive, got {nodes}")
    if relations <= 0:
        raise RuntimeError(f"graph relation count must be positive, got {relations}")


def _verify_integrity(payload: dict[str, Any]) -> None:
    failed = int(payload.get("failed") or 0)
    checks = payload.get("checks") or []
    if failed != 0:
        failed_checks = [
            f"{check.get('name')}={check.get('actual')}"
            for check in checks
            if isinstance(check, dict) and not bool(check.get("passed"))
        ]
        raise RuntimeError(f"graph integrity failed {failed} checks: {', '.join(failed_checks)}")


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
    now: datetime | None = None,
) -> int:
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
    declared_runtime_ids = declared_runtime_ids or set()
    missing = sorted(declared_runtime_ids - set(latest_by_runtime))
    if missing:
        raise RuntimeError(f"missing graph ingest run history for {len(missing)} declared runtime(s): {', '.join(missing)}")
    failed = [run for run in latest_by_runtime.values() if str(run.get("status") or "").strip() == "failed"]
    if failed:
        summary = ", ".join(f"{run.get('runtime_id')}:{run.get('id')}" for run in failed)
        raise RuntimeError(f"latest graph ingest run failed for {len(failed)} runtime(s): {summary}")
    running = [run for run in latest_by_runtime.values() if str(run.get("status") or "").strip() == "running"]
    now = now or datetime.now(UTC)
    stale_running = []
    for run in running:
        started_at = _parse_time(run.get("started_at"))
        if started_at is not None and (now - started_at).total_seconds() > max_running_minutes * 60:
            stale_running.append(run)
    if stale_running:
        summary = ", ".join(f"{run.get('runtime_id')}:{run.get('id')}:{run.get('started_at')}" for run in stale_running)
        raise RuntimeError(f"latest graph ingest run is stale-running for {len(stale_running)} runtime(s): {summary}")
    zero_projection = [
        run
        for run in latest_by_runtime.values()
        if str(run.get("status") or "").strip() == "completed"
        and int(run.get("events_read") or 0) > 0
        and int(run.get("entities_projected") or 0) == 0
        and int(run.get("links_projected") or 0) == 0
    ]
    if zero_projection:
        summary = ", ".join(f"{run.get('runtime_id')}:{run.get('id')}:events={run.get('events_read')}" for run in zero_projection)
        raise RuntimeError(f"latest graph ingest projected no graph records for {len(zero_projection)} runtime(s): {summary}")
    return len(latest_by_runtime)


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
        if "effective_permission" in aws_families:
            required.add("can_perform")
        if "iam_role_trust" in aws_families:
            required.add("can_assume")
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
    if attack_path_relations_supported and "effective_permission" in aws_families and not (relations & AWS_ATTACK_PATH_RELATIONS):
        raise RuntimeError("graph paths missing AWS attack-path privilege relations")
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
    required = _required_graph_relations(aws_families, attack_path_relations_supported)
    missing = sorted(relation for relation in required if counts.get(relation, 0) <= 0)
    if missing:
        raise RuntimeError(f"graph relation counts missing required relation(s): {', '.join(missing)}")
    if attack_path_relations_supported and "effective_permission" in (aws_families or set()):
        if not any(counts.get(relation, 0) > 0 for relation in AWS_ATTACK_PATH_RELATIONS):
            raise RuntimeError("graph relation counts missing AWS attack-path privilege relations")
    return {relation for relation, count in counts.items() if count > 0}


def _is_graph_paths_timeout(exc: Exception) -> bool:
    return "context deadline exceeded" in str(exc).lower()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify live Cerebro graph health through a one-off ECS task.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--wait-timeout-seconds", type=int, default=600)
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--max-running-minutes", type=int, default=DEFAULT_MAX_RUNNING_MINUTES)
    args = parser.parse_args(argv)

    stack = _stack_name(args.stack_file)
    config = _load_config(args.stack_file)
    _verify_account(stack, args.region)
    resource_prefix = _resource_prefix(config, stack)
    service = _describe_api_service(resource_prefix, args.region)
    declared_runtime_ids = _declared_runtime_ids(config)

    counts = _run_graph_command(resource_prefix, service, ["graph", "counts"], args.wait_timeout_seconds, args.poll_seconds, args.region)
    _verify_counts(counts.payload)
    integrity = _run_graph_command(resource_prefix, service, ["graph", "integrity"], args.wait_timeout_seconds, args.poll_seconds, args.region)
    _verify_integrity(integrity.payload)
    aws_families = _declared_aws_families(config)
    attack_path_relations_supported = _supports_attack_path_relations(config)
    graph_relations: set[str] = set()
    paths_task_arn = ""
    if _supports_relation_counts(config):
        required_relations = _required_graph_relations(
            aws_families,
            attack_path_relations_supported=attack_path_relations_supported,
        )
        relation_counts = _run_graph_command(
            resource_prefix,
            service,
            ["graph", "relation-counts", f"relations={','.join(sorted(required_relations | AWS_ATTACK_PATH_RELATIONS))}"],
            args.wait_timeout_seconds,
            args.poll_seconds,
            args.region,
        )
        paths_task_arn = relation_counts.task_arn
        graph_relations = _verify_required_graph_relation_counts(
            relation_counts.payload,
            aws_families,
            attack_path_relations_supported=attack_path_relations_supported,
        )
    else:
        try:
            paths = _run_graph_command(
                resource_prefix,
                service,
                ["graph", "paths", "limit=100"],
                args.wait_timeout_seconds,
                args.poll_seconds,
                args.region,
            )
            paths_task_arn = paths.task_arn
            graph_relations = _verify_required_graph_relations(
                paths.payload,
                aws_families,
                attack_path_relations_supported=attack_path_relations_supported,
            )
        except Exception as exc:
            if not _is_graph_paths_timeout(exc):
                raise
            print(f"WARNING: skipping graph path relation assertions after timeout: {exc}", file=sys.stderr)
    ingest_runs = _run_graph_command(
        resource_prefix,
        service,
        ["graph", "ingest-runs", f"limit={_ingest_run_limit(declared_runtime_ids)}"],
        args.wait_timeout_seconds,
        args.poll_seconds,
        args.region,
    )
    current_ingest_runtimes = _verify_current_ingest_runs(
        ingest_runs.payload,
        max_running_minutes=args.max_running_minutes,
    )

    print("checked_at\tstack\tnodes\trelations\tintegrity_passed\tintegrity_failed\tgraph_relations\tcurrent_ingest_runtimes\tcounts_task\tintegrity_task\tpaths_task\tingest_runs_task")
    print(
        "\t".join(
            [
                datetime.now(UTC).isoformat(),
                stack,
                str(counts.payload.get("nodes")),
                str(counts.payload.get("relations")),
                str(integrity.payload.get("passed")),
                str(integrity.payload.get("failed")),
                ",".join(sorted(graph_relations)),
                str(current_ingest_runtimes),
                counts.task_arn,
                integrity.task_arn,
                paths_task_arn,
                ingest_runs.task_arn,
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
