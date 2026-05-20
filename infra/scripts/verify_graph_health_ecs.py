#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
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


def _aws(args: list[str], region: str) -> Any:
    command = ["aws", *args, "--region", region, "--output", "json"]
    completed = subprocess.run(command, check=True, text=True, capture_output=True)
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


def _wait_for_task(cluster: str, task_arn: str, timeout_seconds: int, poll_seconds: int, region: str) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        tasks = _describe_tasks(cluster, [task_arn], region)
        if tasks and tasks[0].get("lastStatus") == "STOPPED":
            return
        time.sleep(poll_seconds)
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
    overrides = {"containerOverrides": [{"name": "cerebro", "command": command}]}
    response = _aws(
        [
            "ecs",
            "run-task",
            "--cluster",
            cluster,
            "--task-definition",
            service["taskDefinition"],
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify live Cerebro graph health through a one-off ECS task.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--wait-timeout-seconds", type=int, default=300)
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--max-running-minutes", type=int, default=DEFAULT_MAX_RUNNING_MINUTES)
    args = parser.parse_args(argv)

    stack = _stack_name(args.stack_file)
    config = _load_config(args.stack_file)
    _verify_account(stack, args.region)
    resource_prefix = _resource_prefix(config, stack)
    service = _describe_api_service(resource_prefix, args.region)

    counts = _run_graph_command(resource_prefix, service, ["graph", "counts"], args.wait_timeout_seconds, args.poll_seconds, args.region)
    _verify_counts(counts.payload)
    integrity = _run_graph_command(resource_prefix, service, ["graph", "integrity"], args.wait_timeout_seconds, args.poll_seconds, args.region)
    _verify_integrity(integrity.payload)
    ingest_runs = _run_graph_command(
        resource_prefix,
        service,
        ["graph", "ingest-runs", "limit=100"],
        args.wait_timeout_seconds,
        args.poll_seconds,
        args.region,
    )
    current_ingest_runtimes = _verify_current_ingest_runs(
        ingest_runs.payload,
        declared_runtime_ids=_declared_runtime_ids(config),
        max_running_minutes=args.max_running_minutes,
    )

    print("checked_at\tstack\tnodes\trelations\tintegrity_passed\tintegrity_failed\tcurrent_ingest_runtimes\tcounts_task\tintegrity_task\tingest_runs_task")
    print(
        "\t".join(
            [
                datetime.now(UTC).isoformat(),
                stack,
                str(counts.payload.get("nodes")),
                str(counts.payload.get("relations")),
                str(integrity.payload.get("passed")),
                str(integrity.payload.get("failed")),
                str(current_ingest_runtimes),
                counts.task_arn,
                integrity.task_arn,
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
