#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time
from typing import Any

import yaml


DEFAULT_FARGATE_VCPU_HOUR_USD = 0.04048
DEFAULT_FARGATE_GB_HOUR_USD = 0.004445
DEFAULT_SPOT_DISCOUNT = 0.70


@dataclass(frozen=True)
class StackContext:
    stack: str
    environment: str
    resource_name: str
    cluster_name: str
    orchestrator_family: str
    scheduler_group: str
    eventbridge_rule_prefix: str
    task_stop_log_group: str
    cpu_units: int
    memory_mib: int


@dataclass(frozen=True)
class RunConfig:
    task_definition_arn: str
    network_configuration: dict[str, Any]
    capacity_provider_strategy: list[dict[str, Any]]
    launch_type: str


@dataclass(frozen=True)
class TargetCoverage:
    scheduler_schedules: int
    eventbridge_targets: int
    total_targets: int
    spot_targets: int
    fargate_targets: int
    unknown_targets: int
    sample_run_config: RunConfig | None


@dataclass(frozen=True)
class TaskStop:
    task_arn: str
    task_definition_arn: str
    stopped_at: str
    started_at: str
    duration_seconds: float | None
    stop_code: str
    stopped_reason: str
    kind: str
    command: list[str]
    runtime_selector: str
    grouped_runtime_ids: bool
    exit_codes: dict[str, int]
    source: str


@dataclass(frozen=True)
class CostEstimate:
    task_count_with_duration: int
    task_hours: float
    vcpu_hours: float
    memory_gb_hours: float
    on_demand_cost_usd: float
    spot_cost_usd: float
    modeled_savings_usd: float


@dataclass(frozen=True)
class UsageReport:
    generated_at: str
    window_hours: int
    stack: str
    environment: str
    target_coverage: TargetCoverage
    stop_event_source_counts: dict[str, int]
    stop_counts: dict[str, int]
    grouped_stop_counts: dict[str, int]
    singular_stop_counts: dict[str, int]
    cost_estimate: CostEstimate
    spot_interruptions: list[TaskStop]
    nonzero_exits: list[TaskStop]


def _stack_name(path: Path) -> str:
    name = path.name
    if name.startswith("Pulumi.") and name.endswith(".yaml"):
        return name.removeprefix("Pulumi.").removesuffix(".yaml")
    return path.stem


def load_stack_context(path: Path) -> StackContext:
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    config = loaded.get("config") or {}
    if not isinstance(config, dict):
        raise ValueError(f"{path} must contain a top-level config mapping")

    stack = _stack_name(path)
    environment = str(config.get("cerebro:environment") or stack).strip()
    resource_name = f"cerebro-{environment}"
    cpu_units = int(config.get("cerebro:orchestratorCpu") or 1024)
    memory_mib = int(config.get("cerebro:orchestratorMemory") or 2048)
    return StackContext(
        stack=stack,
        environment=environment,
        resource_name=resource_name,
        cluster_name=f"{resource_name}-cluster",
        orchestrator_family=f"{resource_name}-orchestrator",
        scheduler_group=f"{resource_name}-orchestrator",
        eventbridge_rule_prefix=f"{resource_name}-orchestrator",
        task_stop_log_group=f"/aws/events/{resource_name}-orchestrator-task-stops",
        cpu_units=cpu_units,
        memory_mib=memory_mib,
    )


def _aws_base(profile: str, region: str) -> list[str]:
    command = ["aws"]
    if profile:
        command.extend(["--profile", profile])
    if region:
        command.extend(["--region", region])
    return command


def _aws_json(args: list[str], *, profile: str, region: str, allow_missing: bool = False) -> dict[str, Any]:
    command = [*_aws_base(profile, region), *args, "--output", "json"]
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    if completed.returncode != 0:
        stderr = completed.stderr or ""
        if allow_missing and ("ResourceNotFound" in stderr or "ClusterNotFound" in stderr):
            return {}
        raise RuntimeError(f"{shlex.join(command)} failed: {stderr.strip()}")
    if not completed.stdout.strip():
        return {}
    return json.loads(completed.stdout)


def _get_case(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _capacity_provider_name(strategy: dict[str, Any]) -> str:
    return str(_get_case(strategy, "capacityProvider", "CapacityProvider") or "")


def _positive_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _target_uses_spot(ecs_parameters: dict[str, Any]) -> bool:
    for strategy in _get_case(ecs_parameters, "CapacityProviderStrategy", "capacityProviderStrategy", "capacityProviderStrategies") or []:
        if _capacity_provider_name(strategy) == "FARGATE_SPOT":
            if _positive_int(_get_case(strategy, "weight", "Weight")) > 0 or _positive_int(_get_case(strategy, "base", "Base")) > 0:
                return True
    return False


def _target_uses_fargate(ecs_parameters: dict[str, Any]) -> bool:
    launch_type = str(_get_case(ecs_parameters, "LaunchType", "launchType") or "").upper()
    if launch_type == "FARGATE":
        return True
    for strategy in _get_case(ecs_parameters, "CapacityProviderStrategy", "capacityProviderStrategy", "capacityProviderStrategies") or []:
        if _capacity_provider_name(strategy) == "FARGATE":
            if _positive_int(_get_case(strategy, "weight", "Weight")) > 0 or _positive_int(_get_case(strategy, "base", "Base")) > 0:
                return True
    return False


def _normalize_capacity_provider_strategy(ecs_parameters: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = []
    for strategy in _get_case(ecs_parameters, "CapacityProviderStrategy", "capacityProviderStrategy", "capacityProviderStrategies") or []:
        provider = _capacity_provider_name(strategy)
        if not provider:
            continue
        item = {"capacityProvider": provider}
        if _get_case(strategy, "weight", "Weight") is not None:
            item["weight"] = _positive_int(_get_case(strategy, "weight", "Weight"))
        if _get_case(strategy, "base", "Base") is not None:
            item["base"] = _positive_int(_get_case(strategy, "base", "Base"))
        normalized.append(item)
    return normalized


def _normalize_network_configuration(ecs_parameters: dict[str, Any]) -> dict[str, Any]:
    network = _get_case(ecs_parameters, "NetworkConfiguration", "networkConfiguration") or {}
    awsvpc = _get_case(network, "awsvpcConfiguration", "AwsvpcConfiguration") or {}
    subnets = _get_case(awsvpc, "subnets", "Subnets") or []
    security_groups = _get_case(awsvpc, "securityGroups", "SecurityGroups") or []
    assign_public_ip = _get_case(awsvpc, "assignPublicIp", "AssignPublicIp")
    if isinstance(assign_public_ip, bool):
        assign_public_ip = "ENABLED" if assign_public_ip else "DISABLED"
    return {
        "awsvpcConfiguration": {
            "subnets": subnets,
            "securityGroups": security_groups,
            "assignPublicIp": str(assign_public_ip or "DISABLED").upper(),
        }
    }


def _run_config_from_ecs_parameters(ecs_parameters: dict[str, Any]) -> RunConfig | None:
    task_definition_arn = str(_get_case(ecs_parameters, "TaskDefinitionArn", "taskDefinitionArn") or "")
    network_configuration = _normalize_network_configuration(ecs_parameters)
    if not task_definition_arn or not network_configuration["awsvpcConfiguration"]["subnets"]:
        return None
    return RunConfig(
        task_definition_arn=task_definition_arn,
        network_configuration=network_configuration,
        capacity_provider_strategy=_normalize_capacity_provider_strategy(ecs_parameters),
        launch_type=str(_get_case(ecs_parameters, "LaunchType", "launchType") or "FARGATE").upper(),
    )


def describe_target_coverage(context: StackContext, *, profile: str, region: str) -> TargetCoverage:
    scheduler_schedules = 0
    eventbridge_targets = 0
    spot_targets = 0
    fargate_targets = 0
    unknown_targets = 0
    sample_run_config = None

    scheduler = _aws_json(
        ["scheduler", "list-schedules", "--group-name", context.scheduler_group],
        profile=profile,
        region=region,
        allow_missing=True,
    )
    for schedule in scheduler.get("Schedules") or []:
        scheduler_schedules += 1
        schedule_name = str(schedule.get("Name") or "")
        if not schedule_name:
            unknown_targets += 1
            continue
        detail = _aws_json(
            ["scheduler", "get-schedule", "--group-name", context.scheduler_group, "--name", schedule_name],
            profile=profile,
            region=region,
            allow_missing=True,
        )
        ecs_parameters = (detail.get("Target") or {}).get("EcsParameters") or {}
        if _target_uses_spot(ecs_parameters):
            spot_targets += 1
        elif _target_uses_fargate(ecs_parameters):
            fargate_targets += 1
        else:
            unknown_targets += 1
        sample_run_config = sample_run_config or _run_config_from_ecs_parameters(ecs_parameters)

    rules = _aws_json(
        ["events", "list-rules", "--name-prefix", context.eventbridge_rule_prefix],
        profile=profile,
        region=region,
        allow_missing=True,
    )
    for rule in rules.get("Rules") or []:
        rule_name = str(rule.get("Name") or "")
        if not rule_name:
            continue
        targets = _aws_json(
            ["events", "list-targets-by-rule", "--rule", rule_name],
            profile=profile,
            region=region,
            allow_missing=True,
        )
        for target in targets.get("Targets") or []:
            eventbridge_targets += 1
            ecs_parameters = target.get("EcsParameters") or {}
            if _target_uses_spot(ecs_parameters):
                spot_targets += 1
            elif _target_uses_fargate(ecs_parameters):
                fargate_targets += 1
            else:
                unknown_targets += 1
            sample_run_config = sample_run_config or _run_config_from_ecs_parameters(ecs_parameters)

    total_targets = scheduler_schedules + eventbridge_targets
    return TargetCoverage(
        scheduler_schedules=scheduler_schedules,
        eventbridge_targets=eventbridge_targets,
        total_targets=total_targets,
        spot_targets=spot_targets,
        fargate_targets=fargate_targets,
        unknown_targets=unknown_targets,
        sample_run_config=sample_run_config,
    )


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _format_time(value: datetime | None) -> str:
    return value.isoformat().replace("+00:00", "Z") if value else ""


def _task_command(task: dict[str, Any]) -> list[str]:
    overrides = _get_case(task, "overrides", "Overrides") or {}
    container_overrides = _get_case(overrides, "containerOverrides", "ContainerOverrides") or []
    for override in container_overrides:
        name = _get_case(override, "name", "Name")
        if name == "cerebro":
            command = _get_case(override, "command", "Command") or []
            return [str(part) for part in command]
    return []


def _runtime_selector(command: list[str]) -> str:
    for part in command:
        text = str(part).strip()
        if text.startswith("runtime_ids=") or text.startswith("runtime_id="):
            return text
    return ""


def _exit_codes(task: dict[str, Any]) -> dict[str, int]:
    codes = {}
    for container in _get_case(task, "containers", "Containers") or []:
        name = str(_get_case(container, "name", "Name") or "container")
        value = _get_case(container, "exitCode", "ExitCode")
        if value is not None:
            codes[name] = int(value)
    return codes


def _stop_kind(task: dict[str, Any], exit_codes: dict[str, int]) -> str:
    stop_code = str(_get_case(task, "stopCode", "StopCode") or "")
    stopped_reason = str(_get_case(task, "stoppedReason", "StoppedReason") or "")
    stop_text = f"{stop_code} {stopped_reason}".lower()
    if stop_code == "SpotInterruption" or ("spot" in stop_text and "interruption" in stop_text):
        return "spot_interrupted"
    if any(code != 0 for code in exit_codes.values()):
        return "nonzero_exit"
    if stop_code == "TaskFailedToStart":
        return "task_failed_to_start"
    if exit_codes and all(code == 0 for code in exit_codes.values()):
        return "success"
    if stop_code:
        return "stopped"
    return "unknown"


def task_stop_from_task(task: dict[str, Any], *, source: str) -> TaskStop:
    started_at = _parse_time(_get_case(task, "startedAt", "StartedAt"))
    stopped_at = _parse_time(_get_case(task, "stoppedAt", "StoppedAt"))
    duration_seconds = None
    if started_at and stopped_at and stopped_at >= started_at:
        duration_seconds = (stopped_at - started_at).total_seconds()
    command = _task_command(task)
    exit_codes = _exit_codes(task)
    runtime_selector = _runtime_selector(command)
    return TaskStop(
        task_arn=str(_get_case(task, "taskArn", "TaskArn") or ""),
        task_definition_arn=str(_get_case(task, "taskDefinitionArn", "TaskDefinitionArn") or ""),
        stopped_at=_format_time(stopped_at),
        started_at=_format_time(started_at),
        duration_seconds=duration_seconds,
        stop_code=str(_get_case(task, "stopCode", "StopCode") or ""),
        stopped_reason=str(_get_case(task, "stoppedReason", "StoppedReason") or ""),
        kind=_stop_kind(task, exit_codes),
        command=command,
        runtime_selector=runtime_selector,
        grouped_runtime_ids=runtime_selector.startswith("runtime_ids="),
        exit_codes=exit_codes,
        source=source,
    )


def _describe_stopped_tasks(context: StackContext, *, profile: str, region: str, since: datetime) -> list[TaskStop]:
    listed = _aws_json(
        ["ecs", "list-tasks", "--cluster", context.cluster_name, "--family", context.orchestrator_family, "--desired-status", "STOPPED"],
        profile=profile,
        region=region,
        allow_missing=True,
    )
    task_arns = [str(arn) for arn in listed.get("taskArns") or []]
    stops: list[TaskStop] = []
    for index in range(0, len(task_arns), 100):
        chunk = task_arns[index:index + 100]
        if not chunk:
            continue
        described = _aws_json(
            ["ecs", "describe-tasks", "--cluster", context.cluster_name, "--tasks", *chunk],
            profile=profile,
            region=region,
            allow_missing=True,
        )
        for task in described.get("tasks") or []:
            stopped_at = _parse_time(_get_case(task, "stoppedAt", "StoppedAt"))
            if stopped_at and stopped_at < since:
                continue
            stops.append(task_stop_from_task(task, source="ecs"))
    return stops


def _cloudwatch_stopped_task_events(
    context: StackContext,
    *,
    profile: str,
    region: str,
    since: datetime,
    until: datetime,
) -> list[TaskStop]:
    response = _aws_json(
        [
            "logs",
            "filter-log-events",
            "--log-group-name",
            context.task_stop_log_group,
            "--start-time",
            str(int(since.timestamp() * 1000)),
            "--end-time",
            str(int(until.timestamp() * 1000)),
        ],
        profile=profile,
        region=region,
        allow_missing=True,
    )
    stops: list[TaskStop] = []
    for event in response.get("events") or []:
        message = str(event.get("message") or "")
        if not message:
            continue
        try:
            payload = json.loads(message)
        except json.JSONDecodeError:
            continue
        detail = payload.get("detail") or payload
        if not isinstance(detail, dict):
            continue
        stops.append(task_stop_from_task(detail, source="cloudwatch"))
    return stops


def load_stopped_tasks(context: StackContext, *, profile: str, region: str, window_hours: int) -> list[TaskStop]:
    until = datetime.now(UTC)
    since = until - timedelta(hours=window_hours)
    by_task_arn: dict[str, TaskStop] = {}
    for stop in _describe_stopped_tasks(context, profile=profile, region=region, since=since):
        if stop.task_arn:
            by_task_arn[stop.task_arn] = stop
    for stop in _cloudwatch_stopped_task_events(context, profile=profile, region=region, since=since, until=until):
        if stop.task_arn and stop.task_arn not in by_task_arn:
            by_task_arn[stop.task_arn] = stop
    return sorted(by_task_arn.values(), key=lambda stop: stop.stopped_at, reverse=True)


def _count_by_kind(stops: list[TaskStop]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for stop in stops:
        counts[stop.kind] = counts.get(stop.kind, 0) + 1
    return dict(sorted(counts.items()))


def _count_by_source(stops: list[TaskStop]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for stop in stops:
        counts[stop.source] = counts.get(stop.source, 0) + 1
    return dict(sorted(counts.items()))


def estimate_cost(
    stops: list[TaskStop],
    context: StackContext,
    *,
    vcpu_hour_usd: float = DEFAULT_FARGATE_VCPU_HOUR_USD,
    gb_hour_usd: float = DEFAULT_FARGATE_GB_HOUR_USD,
    spot_discount: float = DEFAULT_SPOT_DISCOUNT,
) -> CostEstimate:
    task_hours = sum((stop.duration_seconds or 0) for stop in stops) / 3600
    vcpu_hours = task_hours * (context.cpu_units / 1024)
    memory_gb_hours = task_hours * (context.memory_mib / 1024)
    on_demand_cost = (vcpu_hours * vcpu_hour_usd) + (memory_gb_hours * gb_hour_usd)
    spot_cost = on_demand_cost * max(0.0, 1 - spot_discount)
    return CostEstimate(
        task_count_with_duration=sum(1 for stop in stops if stop.duration_seconds is not None),
        task_hours=round(task_hours, 4),
        vcpu_hours=round(vcpu_hours, 4),
        memory_gb_hours=round(memory_gb_hours, 4),
        on_demand_cost_usd=round(on_demand_cost, 4),
        spot_cost_usd=round(spot_cost, 4),
        modeled_savings_usd=round(on_demand_cost - spot_cost, 4),
    )


def build_report(
    context: StackContext,
    coverage: TargetCoverage,
    stops: list[TaskStop],
    *,
    window_hours: int,
    vcpu_hour_usd: float,
    gb_hour_usd: float,
    spot_discount: float,
) -> UsageReport:
    grouped = [stop for stop in stops if stop.grouped_runtime_ids]
    singular = [stop for stop in stops if stop.runtime_selector.startswith("runtime_id=")]
    return UsageReport(
        generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        window_hours=window_hours,
        stack=context.stack,
        environment=context.environment,
        target_coverage=coverage,
        stop_event_source_counts=_count_by_source(stops),
        stop_counts=_count_by_kind(stops),
        grouped_stop_counts=_count_by_kind(grouped),
        singular_stop_counts=_count_by_kind(singular),
        cost_estimate=estimate_cost(
            stops,
            context,
            vcpu_hour_usd=vcpu_hour_usd,
            gb_hour_usd=gb_hour_usd,
            spot_discount=spot_discount,
        ),
        spot_interruptions=[stop for stop in stops if stop.kind == "spot_interrupted"],
        nonzero_exits=[stop for stop in stops if stop.kind == "nonzero_exit"],
    )


def build_replay_command(
    context: StackContext,
    stop: TaskStop,
    run_config: RunConfig,
    *,
    profile: str,
    region: str,
    replay_capacity_provider: str,
) -> list[str]:
    if stop.kind != "spot_interrupted":
        raise ValueError("only Spot-interrupted tasks can be replayed")
    if not stop.command:
        raise ValueError("interrupted task does not include a cerebro container command override")
    started_by_hash = hashlib.sha256(stop.task_arn.encode("utf-8")).hexdigest()[:32]
    command = [
        *_aws_base(profile, region),
        "ecs",
        "run-task",
        "--cluster",
        context.cluster_name,
        "--task-definition",
        stop.task_definition_arn or run_config.task_definition_arn,
        "--network-configuration",
        json.dumps(run_config.network_configuration, separators=(",", ":")),
        "--overrides",
        json.dumps({"containerOverrides": [{"name": "cerebro", "command": stop.command}]}, separators=(",", ":")),
        "--started-by",
        f"cerebro-spot-replay-{started_by_hash}",
    ]
    if replay_capacity_provider:
        command.extend([
            "--capacity-provider-strategy",
            json.dumps([{"capacityProvider": replay_capacity_provider, "weight": 1}], separators=(",", ":")),
        ])
    elif run_config.capacity_provider_strategy:
        command.extend([
            "--capacity-provider-strategy",
            json.dumps(run_config.capacity_provider_strategy, separators=(",", ":")),
        ])
    else:
        command.extend(["--launch-type", run_config.launch_type or "FARGATE"])
    command.extend(["--output", "json"])
    return command


def _report_as_dict(report: UsageReport) -> dict[str, Any]:
    return asdict(report)


def _print_text_report(report: UsageReport) -> None:
    coverage = report.target_coverage
    estimate = report.cost_estimate
    print(f"generated_at: {report.generated_at}")
    print(f"stack: {report.stack}")
    print(f"environment: {report.environment}")
    print(f"window_hours: {report.window_hours}")
    print(
        "target_coverage: "
        f"{coverage.spot_targets}/{coverage.total_targets} targets on FARGATE_SPOT "
        f"(scheduler={coverage.scheduler_schedules}, eventbridge={coverage.eventbridge_targets}, "
        f"fargate={coverage.fargate_targets}, unknown={coverage.unknown_targets})"
    )
    print(f"stopped_tasks: {report.stop_counts}")
    print(f"stopped_task_sources: {report.stop_event_source_counts}")
    print(f"grouped_runtime_ids_stopped_tasks: {report.grouped_stop_counts}")
    print(f"singular_runtime_id_stopped_tasks: {report.singular_stop_counts}")
    print(
        "modeled_cost: "
        f"task_hours={estimate.task_hours}, vcpu_hours={estimate.vcpu_hours}, "
        f"memory_gb_hours={estimate.memory_gb_hours}, on_demand=${estimate.on_demand_cost_usd}, "
        f"spot=${estimate.spot_cost_usd}, savings=${estimate.modeled_savings_usd}"
    )
    if report.spot_interruptions:
        print("spot_interruptions:")
        for stop in report.spot_interruptions:
            print(f"- {stop.stopped_at} {stop.runtime_selector or '[all]'} {stop.task_definition_arn} {stop.stopped_reason}")
    if report.nonzero_exits:
        print("nonzero_exits:")
        for stop in report.nonzero_exits:
            print(f"- {stop.stopped_at} {stop.runtime_selector or '[all]'} exit_codes={stop.exit_codes}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Report Cerebro orchestrator Spot usage, savings, and replayable interruptions.")
    parser.add_argument("--stack-file", type=Path, required=True, help="AWS Pulumi stack file, for example infra/aws/Pulumi.go-prod.yaml")
    parser.add_argument("--profile", required=True, help="AWS SSO profile to use")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--window-hours", type=int, default=48)
    parser.add_argument("--vcpu-hour-usd", type=float, default=DEFAULT_FARGATE_VCPU_HOUR_USD)
    parser.add_argument("--gb-hour-usd", type=float, default=DEFAULT_FARGATE_GB_HOUR_USD)
    parser.add_argument("--spot-discount", type=float, default=DEFAULT_SPOT_DISCOUNT)
    parser.add_argument("--output", choices=("text", "json"), default="text")
    parser.add_argument("--emit-replay-commands", action="store_true", help="Print aws ecs run-task commands for Spot-interrupted tasks.")
    parser.add_argument("--replay-interrupted", action="store_true", help="Run replay commands for Spot-interrupted tasks.")
    parser.add_argument("--max-replays", type=int, default=10)
    parser.add_argument(
        "--replay-capacity-provider",
        default="FARGATE",
        help="Capacity provider for interrupted replay tasks; defaults to FARGATE for reliability. Use an empty string to reuse the scheduled target strategy.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    context = load_stack_context(args.stack_file)
    coverage = describe_target_coverage(context, profile=args.profile, region=args.region)
    stops = load_stopped_tasks(context, profile=args.profile, region=args.region, window_hours=args.window_hours)
    report = build_report(
        context,
        coverage,
        stops,
        window_hours=args.window_hours,
        vcpu_hour_usd=args.vcpu_hour_usd,
        gb_hour_usd=args.gb_hour_usd,
        spot_discount=args.spot_discount,
    )

    if args.output == "json":
        print(json.dumps(_report_as_dict(report), indent=2, sort_keys=True))
    else:
        _print_text_report(report)

    if args.emit_replay_commands or args.replay_interrupted:
        if not coverage.sample_run_config:
            print("No replay commands emitted: no Scheduler/EventBridge ECS network configuration was found.", file=sys.stderr)
            return 2
        interrupted = [stop for stop in stops if stop.kind == "spot_interrupted" and stop.command][:args.max_replays]
        for stop in interrupted:
            command = build_replay_command(
                context,
                stop,
                coverage.sample_run_config,
                profile=args.profile,
                region=args.region,
                replay_capacity_provider=args.replay_capacity_provider,
            )
            if args.emit_replay_commands:
                print(shlex.join(command))
            if args.replay_interrupted:
                completed = subprocess.run(command, check=False, text=True, capture_output=True)
                if completed.stdout.strip():
                    print(completed.stdout.strip())
                if completed.returncode != 0:
                    print((completed.stderr or "").strip(), file=sys.stderr)
                    return completed.returncode
                time.sleep(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
