#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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


@dataclass(frozen=True)
class RuntimeTarget:
    runtime_id: str
    schedule_name: str
    rule_name: str
    target: dict[str, Any]


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


class RuntimeSkippedError(RuntimeError):
    def __init__(self, runtime_id: str, task_arn: str, reason: str) -> None:
        self.runtime_id = runtime_id
        self.task_arn = task_arn
        self.reason = reason
        detail = f" ({reason})" if reason else ""
        super().__init__(f"{runtime_id} orchestrator runtime status is skipped{detail}: {task_arn}")


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


def _runtime_id_from_command(command: Any) -> str:
    if not isinstance(command, list):
        return ""
    for arg in command:
        text = str(arg).strip()
        if text.startswith("runtime_id="):
            return text.split("=", 1)[1].strip()
    return ""


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
    runtimes = config.get("sourceRuntimes") or []
    if not isinstance(runtimes, list):
        return []
    runtime_ids = []
    families = families or set()
    for runtime in runtimes:
        if not isinstance(runtime, dict):
            continue
        runtime_id = str(runtime.get("id", "")).strip()
        runtime_source_id = str(runtime.get("sourceId") or runtime.get("source_id") or "").strip()
        runtime_config = runtime.get("config") or {}
        family = str(runtime_config.get("family") or "").strip() if isinstance(runtime_config, dict) else ""
        if (
            runtime_id
            and runtime_source_id == source_id
            and (not requested or runtime_id in requested)
            and (not families or family in families)
        ):
            runtime_ids.append(runtime_id)
    return sorted(runtime_ids)


def _runtime_targets(config: dict[str, Any], runtime_ids: list[str], resource_prefix: str, region: str) -> list[RuntimeTarget]:
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
        schedule_name = str(schedule.get("name") or runtime_id)
        suffix = _schedule_suffix(schedule_name)
        rule_name = f"{resource_prefix}-orchestrator" if suffix == "default" else f"{resource_prefix}-orchestrator-{suffix}"
        response = _aws(["events", "list-targets-by-rule", "--rule", rule_name], region)
        rule_targets = response.get("Targets") or []
        if len(rule_targets) != 1:
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
    print(f"Using latest active ECS task definition {replacement} instead of inactive {task_definition}", file=sys.stderr)
    return replacement


def _run_task(target: RuntimeTarget, region: str) -> str:
    ecs_params = target.target["EcsParameters"]
    network = ecs_params["NetworkConfiguration"]["awsvpcConfiguration"]
    subnets = ",".join(network["Subnets"])
    security_groups = ",".join(network["SecurityGroups"])
    assign_public_ip = network.get("AssignPublicIp", "DISABLED")
    task_definition = _latest_active_task_definition(ecs_params["TaskDefinitionArn"], region)
    response = _aws(
        [
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
        ],
        region,
    )
    failures = response.get("failures") or []
    if failures:
        raise RuntimeError(f"failed to start {target.runtime_id}: {failures}")
    tasks = response.get("tasks") or []
    if len(tasks) != 1:
        raise RuntimeError(f"expected one task for {target.runtime_id}, got {len(tasks)}")
    return tasks[0]["taskArn"]


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
            "10",
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


def _wait_for_task(cluster_arn: str, task_arn: str, timeout_seconds: int, poll_seconds: int, region: str) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        tasks = _describe_tasks(cluster_arn, [task_arn], region)
        if tasks and tasks[0].get("lastStatus") == "STOPPED":
            return
        time.sleep(poll_seconds)
    raise TimeoutError(f"task {task_arn} did not stop within {timeout_seconds} seconds")


def _task_id(task_arn: str) -> str:
    return task_arn.rsplit("/", 1)[-1]


def _task_logs(task: dict[str, Any], region: str) -> list[dict[str, Any]]:
    task_definition = task["taskDefinitionArn"]
    response = _aws(["ecs", "describe-task-definition", "--task-definition", task_definition], region)
    container_definitions = response["taskDefinition"]["containerDefinitions"]
    cerebro_container = next(container for container in container_definitions if container.get("name") == "cerebro")
    options = cerebro_container["logConfiguration"]["options"]
    log_group = options["awslogs-group"]
    stream_prefix = options["awslogs-stream-prefix"]
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
            "400",
        ],
        region,
    )
    messages = []
    for event in events.get("events") or []:
        try:
            messages.append(json.loads(event.get("message") or "{}"))
        except json.JSONDecodeError:
            continue
    return messages


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
    )
    lines = []
    for message in messages[-limit:]:
        summary = {key: message[key] for key in keys if key in message}
        if summary:
            line = json.dumps(summary, sort_keys=True)
        else:
            line = json.dumps(message, sort_keys=True)
        lines.append(line[:2000])
    return "\n".join(lines)


def _latest_span(messages: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for message in reversed(messages):
        if message.get("kind") == "span_end" and message.get("name") == name:
            return message
    return None


def _runtime_skip_reason(runtime_span: dict[str, Any] | None) -> str:
    if not runtime_span:
        return ""
    return str(runtime_span.get("reason") or "").strip()


def _runtime_skip_retryable(reason: str) -> bool:
    return reason == "lease_not_acquired"


def _verify_task(target: RuntimeTarget, task_arn: str, region: str) -> VerificationResult:
    task = _describe_tasks(target.target["Arn"], [task_arn], region)[0]
    containers = task.get("containers") or []
    cerebro_container = next((container for container in containers if container.get("name") == "cerebro"), None)
    exit_code = cerebro_container.get("exitCode") if cerebro_container else None
    if exit_code != 0:
        try:
            log_summary = _summarize_log_messages(_task_logs(task, region))
        except Exception as exc:
            log_summary = f"unable to fetch task logs: {exc}"
        detail = f"\nRecent task logs:\n{log_summary}" if log_summary else ""
        raise RuntimeError(f"{target.runtime_id} task exited with {exit_code}: {task_arn}{detail}")

    messages = _task_logs(task, region)
    runtime_span = _latest_span(messages, "orchestrator.runtime")
    sync_span = _latest_span(messages, "source_runtime.sync")
    graph_ingest_span = _latest_span(messages, "orchestrator.graph_ingest")
    runtime_status = str((runtime_span or {}).get("status") or "missing")
    sync_status = str((sync_span or {}).get("status") or "missing")
    graph_ingest_status = str((graph_ingest_span or {}).get("status") or "missing")
    if runtime_status == "skipped":
        raise RuntimeSkippedError(target.runtime_id, task_arn, _runtime_skip_reason(runtime_span))
    if runtime_status != "completed":
        raise RuntimeError(f"{target.runtime_id} orchestrator runtime status is {runtime_status}")
    if sync_status != "completed":
        raise RuntimeError(f"{target.runtime_id} source sync status is {sync_status}")
    if graph_ingest_status != "completed":
        raise RuntimeError(f"{target.runtime_id} graph ingest status is {graph_ingest_status}")

    return VerificationResult(
        runtime_id=target.runtime_id,
        task_arn=task_arn,
        exit_code=exit_code,
        runtime_status=runtime_status,
        sync_status=sync_status,
        graph_ingest_status=graph_ingest_status,
        events_appended=sync_span.get("events_appended") if sync_span else None,
        pages_read=sync_span.get("pages_read") if sync_span else None,
    )


def _run_and_verify_task_with_retries(
    target: RuntimeTarget,
    wait_timeout_seconds: int,
    poll_seconds: int,
    region: str,
) -> VerificationResult:
    deadline = time.time() + wait_timeout_seconds
    while True:
        remaining = max(1, int(deadline - time.time()))
        task_arn = _run_task(target, region)
        _wait_for_task(target.target["Arn"], task_arn, remaining, poll_seconds, region)
        try:
            return _verify_task(target, task_arn, region)
        except RuntimeSkippedError as exc:
            if not _runtime_skip_retryable(exc.reason):
                raise
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


def _verify_account(stack: str, region: str) -> None:
    expected = EXPECTED_STACK_ACCOUNTS.get(stack)
    if not expected:
        return
    caller = _aws(["sts", "get-caller-identity"], region)
    actual = str(caller.get("Account", ""))
    if actual != expected:
        raise RuntimeError(f"stack {stack} must run in AWS account {expected}, got {actual}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify ECS source runtime executions from GitOps-declared schedules.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--source-id", default="cosmo")
    parser.add_argument("--runtime-id", action="append", default=[])
    parser.add_argument("--family", action="append", default=[], help="Restrict verification to source runtimes with this config family.")
    parser.add_argument("--run", action="store_true", help="Start each runtime from its EventBridge target before verifying.")
    parser.add_argument("--max-age-minutes", type=int, default=180)
    parser.add_argument("--wait-timeout-seconds", type=int, default=900)
    parser.add_argument("--poll-seconds", type=int, default=10)
    args = parser.parse_args(argv)

    stack = _stack_name(args.stack_file)
    config = _load_config(args.stack_file)
    environment = str(config.get("environment") or stack)
    resource_prefix = f"cerebro-{environment}"
    requested = set(args.runtime_id or [])
    families = set(args.family or [])
    runtime_ids = _declared_runtime_ids(config, args.source_id, requested, families)
    if not runtime_ids:
        scope = f" source {args.source_id!r}"
        if families:
            scope += f" and family {', '.join(sorted(families))!r}"
        raise RuntimeError(f"no declared source runtimes found for{scope}")

    _verify_account(stack, args.region)
    targets = _runtime_targets(config, runtime_ids, resource_prefix, args.region)
    results = []
    for target in targets:
        if args.run:
            results.append(
                _run_and_verify_task_with_retries(
                    target,
                    args.wait_timeout_seconds,
                    args.poll_seconds,
                    args.region,
                )
            )
        else:
            task_arn = _latest_task(target, args.max_age_minutes, args.region)
            results.append(_verify_task(target, task_arn, args.region))

    print("runtime_id\texit\tsync\tevents_appended\tpages_read\tgraph_ingest\ttask_arn")
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
                    result.task_arn,
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
