#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


MIN_CROSS_TASK_SYNC_LOCK_VERSION = (2, 1, 25)
MIN_COSMO_TOKEN_AUTH_VERSION = (2, 1, 36)
MIN_AWS_EFFECTIVE_PERMISSION_VERSION = (2, 1, 46)
IMAGE_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$")
SECRET_KEY_RE = re.compile(r"(secret|token|password|api_?key|client_secret|private_key)", re.IGNORECASE)
AWS_ROLE_ARN_RE = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$")
COSMO_REQUIRED_STACKS = {"sec-dev", "go-prod"}
COSMO_REQUIRED_SECRETS = {"CEREBRO_SOURCE_COSMO_BASE_URL", "CEREBRO_SOURCE_COSMO_EXPORT_SECRET", "CEREBRO_SOURCE_COSMO_TOKEN"}
COSMO_RUNTIME_FAMILIES = {
    "writer-cosmo-session": "session",
    "writer-cosmo-fact": "fact",
    "writer-cosmo-message": "message",
    "writer-cosmo-survey-feedback": "survey_feedback",
}
SEC_DEV_HIGH_CONTENTION_GRAPH_RUNTIMES = {
    "writer-github-audit",
    "writer-github-audit-writerinternal",
    "writer-okta-audit",
    "writer-okta-audit-2026-04",
    "writer-okta-audit-2026-q1",
}
SEC_DEV_MAX_HIGH_CONTENTION_PAGE_LIMIT = 5
SEC_DEV_MAX_HIGH_CONTENTION_GRAPH_PAGE_LIMIT = 5
PROD_HIGH_CONTENTION_GRAPH_RUNTIMES = {
    "writer-grc-vulnerable-asset",
    "writer-vulnview-dns-alert",
    "writer-vulnview-vulnerability",
}
PROD_MAX_HIGH_CONTENTION_PAGE_LIMIT = 1
PROD_MAX_HIGH_CONTENTION_GRAPH_PAGE_LIMIT = 1
SEC_DEV_AWS_ACCOUNT_ID = "944130631940"
SEC_DEV_AWS_ROLE_ARN = "arn:aws:iam::944130631940:role/cerebro-org-scan-role"
SEC_DEV_AWS_GLOBAL_FAMILIES = {
    "access_key",
    "effective_permission",
    "iam_group",
    "iam_group_membership",
    "iam_role",
    "iam_role_assignment",
    "iam_role_trust",
    "iam_user",
}
SEC_DEV_AWS_REGIONAL_FAMILIES = {"cloudtrail", "public_endpoint", "resource_exposure"}
SEC_DEV_AWS_CLOUDTRAIL_SINCE = "PT15M"


@dataclass(frozen=True)
class Finding:
    severity: str
    stack: str
    path: str
    message: str


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
    result: dict[str, Any] = {}
    for key, value in config.items():
        if isinstance(key, str) and key.startswith("cerebro:"):
            result[key.removeprefix("cerebro:")] = value
    return result


def _parse_image_tag(image_tag: str) -> tuple[int, int, int] | None:
    match = IMAGE_TAG_RE.match(image_tag)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _supports_cross_task_sync_lock(image_tag: str) -> bool:
    parsed = _parse_image_tag(image_tag)
    return parsed is not None and parsed >= MIN_CROSS_TASK_SYNC_LOCK_VERSION


def _env_refs(value: Any, path: str = "") -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("env:"):
            env_name = stripped.removeprefix("env:").strip()
            refs.append((env_name, path))
    elif isinstance(value, dict):
        for key, child in value.items():
            refs.extend(_env_refs(child, f"{path}.{key}" if path else str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            refs.extend(_env_refs(child, f"{path}[{index}]"))
    return refs


def _source_secret_names(source_secret_keys: Any) -> set[str]:
    names: set[str] = set()
    if not isinstance(source_secret_keys, list):
        return names
    for entry in source_secret_keys:
        if isinstance(entry, str):
            names.add(entry.strip())
        elif isinstance(entry, dict):
            name = str(entry.get("name", "")).strip()
            if name:
                names.add(name)
    return names


def _s3_source_role_requirements(s3_sources: Any) -> list[tuple[str, str, str]]:
    requirements: list[tuple[str, str, str]] = []
    if not isinstance(s3_sources, list):
        return requirements
    for source in s3_sources:
        if not isinstance(source, dict):
            continue
        role_arn = str(source.get("roleArn", "")).strip()
        bucket = str(source.get("bucket", "")).strip()
        prefixes = source.get("prefixes") or []
        if not role_arn or not bucket or not isinstance(prefixes, list):
            continue
        for prefix in prefixes:
            prefix_text = str(prefix).strip()
            if prefix_text:
                requirements.append((bucket, prefix_text, role_arn))
    return requirements


def _runtime_id_from_command(command: Any) -> str | None:
    if not isinstance(command, list):
        return None
    for arg in command:
        text = str(arg).strip()
        if text.startswith("runtime_id="):
            runtime_id = text.split("=", 1)[1].strip()
            return runtime_id or None
    return None


def _uint_arg_from_command(command: Any, key: str) -> int | None:
    if not isinstance(command, list):
        return None
    prefix = f"{key}="
    for arg in command:
        text = str(arg).strip()
        if not text.startswith(prefix):
            continue
        value = text.removeprefix(prefix).strip()
        if not value:
            return None
        try:
            parsed = int(value)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


def _is_plain_secret(key: str, value: Any) -> bool:
    if not SECRET_KEY_RE.search(key):
        return False
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    return bool(stripped) and not stripped.startswith("env:") and not stripped.startswith("${")


def _parse_retirement_date(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _finding(severity: str, stack: str, path: str, message: str) -> Finding:
    return Finding(severity=severity, stack=stack, path=path, message=message)


def _validate_graph_page_budget(stack: str, runtime_id: str, command: Any, path: str, findings: list[Finding]) -> None:
    if stack == "sec-dev" and runtime_id in SEC_DEV_HIGH_CONTENTION_GRAPH_RUNTIMES:
        max_page_limit = SEC_DEV_MAX_HIGH_CONTENTION_PAGE_LIMIT
        max_graph_page_limit = SEC_DEV_MAX_HIGH_CONTENTION_GRAPH_PAGE_LIMIT
    elif stack == "go-prod" and runtime_id in PROD_HIGH_CONTENTION_GRAPH_RUNTIMES:
        max_page_limit = PROD_MAX_HIGH_CONTENTION_PAGE_LIMIT
        max_graph_page_limit = PROD_MAX_HIGH_CONTENTION_GRAPH_PAGE_LIMIT
    else:
        return

    page_limit = _uint_arg_from_command(command, "page_limit")
    if page_limit is not None and page_limit > max_page_limit:
        findings.append(
            _finding(
                "error",
                stack,
                path,
                f"high-contention graph source sync for {runtime_id} must set page_limit <= {max_page_limit}",
            )
        )
    graph_page_limit = _uint_arg_from_command(command, "graph_page_limit")
    if graph_page_limit is not None and graph_page_limit > max_graph_page_limit:
        findings.append(
            _finding(
                "error",
                stack,
                path,
                f"high-contention graph ingest for {runtime_id} must set graph_page_limit <= {max_graph_page_limit}",
            )
        )


def _validate_cosmo_gitops(
    stack: str,
    config: dict[str, Any],
    source_runtimes: list[Any],
    schedules: list[Any],
    source_secret_names: set[str],
    findings: list[Finding],
) -> None:
    if stack not in COSMO_REQUIRED_STACKS:
        return

    image_tag = str(config.get("imageTag", "")).strip()
    parsed_tag = _parse_image_tag(image_tag)
    if parsed_tag is not None and parsed_tag < MIN_COSMO_TOKEN_AUTH_VERSION:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:imageTag",
                "Cosmo survey feedback token auth requires cerebro:imageTag >= v2.1.36",
            )
        )

    for secret_name in sorted(COSMO_REQUIRED_SECRETS):
        if secret_name not in source_secret_names:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:sourceSecretKeys",
                    f"Cosmo secret {secret_name!r} must be declared for GitOps-managed imports",
                )
            )
    if "CEREBRO_SOURCE_COSMO_WEBHOOK_SECRET" in source_secret_names:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:sourceSecretKeys",
                "Cosmo survey feedback must use CEREBRO_SOURCE_COSMO_TOKEN, not the legacy webhook secret",
            )
        )

    runtimes_by_id: dict[str, tuple[int, dict[str, Any]]] = {}
    for index, runtime in enumerate(source_runtimes):
        if isinstance(runtime, dict):
            runtime_id = str(runtime.get("id", "")).strip()
            if runtime_id:
                runtimes_by_id[runtime_id] = (index, runtime)

    schedules_by_runtime: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, schedule in enumerate(schedules):
        if isinstance(schedule, dict):
            runtime_id = _runtime_id_from_command(schedule.get("command"))
            if runtime_id:
                schedules_by_runtime.setdefault(runtime_id, []).append((index, schedule))

    for runtime_id, family in COSMO_RUNTIME_FAMILIES.items():
        runtime_entry = runtimes_by_id.get(runtime_id)
        if runtime_entry is None:
            findings.append(_finding("error", stack, "cerebro:sourceRuntimes", f"required Cosmo runtime {runtime_id!r} is missing"))
        else:
            runtime_index, runtime = runtime_entry
            runtime_path = f"cerebro:sourceRuntimes[{runtime_index}]"
            if str(runtime.get("sourceId", "")).strip() != "cosmo":
                findings.append(_finding("error", stack, f"{runtime_path}.sourceId", f"{runtime_id} must use sourceId cosmo"))
            if str(runtime.get("tenantId", "")).strip() != "writer":
                findings.append(_finding("error", stack, f"{runtime_path}.tenantId", f"{runtime_id} must use tenantId writer"))

            runtime_config = runtime.get("config") or {}
            if isinstance(runtime_config, dict):
                expected_values = {
                    "base_url": "env:CEREBRO_SOURCE_COSMO_BASE_URL",
                    "token": "env:CEREBRO_SOURCE_COSMO_TOKEN",
                    "tenant_id": "writer",
                    "family": family,
                }
                if family == "message":
                    expected_values.update(
                        {
                            "client_id": "cerebro-runtime",
                            "event_types": "message,completion",
                            "export_secret": "env:CEREBRO_SOURCE_COSMO_EXPORT_SECRET",
                            "max_window_hours": "24",
                            "per_page": "100",
                            "since": "2026-01-01T00:00:00Z",
                        }
                    )
                for key, expected in expected_values.items():
                    actual = str(runtime_config.get(key, "")).strip()
                    if actual != expected:
                        findings.append(_finding("error", stack, f"{runtime_path}.config.{key}", f"{runtime_id} must set {key} to {expected!r}"))
                if "webhook_secret" in runtime_config:
                    findings.append(
                        _finding(
                            "error",
                            stack,
                            f"{runtime_path}.config.webhook_secret",
                            "Cosmo survey feedback must use token auth, not webhook_secret",
                        )
                    )

        schedule_entries = schedules_by_runtime.get(runtime_id, [])
        if not schedule_entries:
            findings.append(_finding("error", stack, "cerebro:orchestratorSchedules", f"required Cosmo schedule for {runtime_id!r} is missing"))
        elif len(schedule_entries) > 1:
            findings.append(_finding("error", stack, "cerebro:orchestratorSchedules", f"Cosmo runtime {runtime_id!r} must have exactly one schedule"))
        else:
            schedule_index, schedule = schedule_entries[0]
            schedule_path = f"cerebro:orchestratorSchedules[{schedule_index}]"
            expected_name = runtime_id.removeprefix("writer-")
            if str(schedule.get("name", "")).strip() != expected_name:
                findings.append(_finding("error", stack, f"{schedule_path}.name", f"{runtime_id} schedule must be named {expected_name!r}"))
            if schedule.get("taskCount", 1) != 1:
                findings.append(_finding("error", stack, f"{schedule_path}.taskCount", f"{runtime_id} schedule must run exactly one task"))


def _validate_sec_dev_aws_coverage(
    stack: str,
    config: dict[str, Any],
    source_runtimes: list[Any],
    schedules: list[Any],
    findings: list[Finding],
) -> None:
    if stack != "sec-dev":
        return

    runtime_entries: dict[str, tuple[int, dict[str, Any]]] = {}
    aws_public_regions: set[str] = set()
    for index, runtime in enumerate(source_runtimes):
        if not isinstance(runtime, dict):
            continue
        runtime_id = str(runtime.get("id", "")).strip()
        if runtime_id:
            runtime_entries[runtime_id] = (index, runtime)
        if str(runtime.get("sourceId", "")).strip() != "aws":
            continue
        runtime_config = runtime.get("config") or {}
        if not isinstance(runtime_config, dict):
            continue
        if str(runtime_config.get("family", "")).strip() == "public_endpoint":
            region = str(runtime_config.get("region", "")).strip()
            if region:
                aws_public_regions.add(region)

    if not aws_public_regions:
        return

    image_tag = str(config.get("imageTag", "")).strip()
    parsed_tag = _parse_image_tag(image_tag)
    if parsed_tag is not None and parsed_tag < MIN_AWS_EFFECTIVE_PERMISSION_VERSION:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:imageTag",
                f"AWS effective_permission and since={SEC_DEV_AWS_CLOUDTRAIL_SINCE} CloudTrail runtimes require cerebro:imageTag >= v2.1.46",
            )
        )

    schedules_by_runtime: dict[str, list[int]] = {}
    for index, schedule in enumerate(schedules):
        if isinstance(schedule, dict):
            runtime_id = _runtime_id_from_command(schedule.get("command"))
            if runtime_id:
                schedules_by_runtime.setdefault(runtime_id, []).append(index)

    required: dict[str, dict[str, str]] = {}
    for family in sorted(SEC_DEV_AWS_GLOBAL_FAMILIES):
        required[f"writer-aws-sec-dev-{family.replace('_', '-')}"] = {
            "account_id": SEC_DEV_AWS_ACCOUNT_ID,
            "family": family,
            "include_global": "true",
            "region": "us-east-1",
            "role_arn": SEC_DEV_AWS_ROLE_ARN,
        }
    for region in sorted(aws_public_regions):
        region_slug = "us1" if region == "us-east-1" else "us2" if region == "us-west-2" else region.replace("-", "")
        for family in sorted(SEC_DEV_AWS_REGIONAL_FAMILIES):
            runtime_id = f"writer-aws-sec-dev-{region_slug}-{family.replace('_', '-')}"
            required[runtime_id] = {
                "account_id": SEC_DEV_AWS_ACCOUNT_ID,
                "family": family,
                "include_global": "true" if region == "us-east-1" else "false",
                "per_page": "100",
                "region": region,
                "role_arn": SEC_DEV_AWS_ROLE_ARN,
            }
            if family == "cloudtrail":
                required[runtime_id]["since"] = SEC_DEV_AWS_CLOUDTRAIL_SINCE

    for runtime_id, expected_config in sorted(required.items()):
        runtime_entry = runtime_entries.get(runtime_id)
        if runtime_entry is None:
            findings.append(_finding("error", stack, "cerebro:sourceRuntimes", f"required sec-dev AWS coverage runtime {runtime_id!r} is missing"))
            continue
        runtime_index, runtime = runtime_entry
        runtime_path = f"cerebro:sourceRuntimes[{runtime_index}]"
        if str(runtime.get("sourceId", "")).strip() != "aws":
            findings.append(_finding("error", stack, f"{runtime_path}.sourceId", f"{runtime_id} must use sourceId aws"))
        if str(runtime.get("tenantId", "")).strip() != "writer":
            findings.append(_finding("error", stack, f"{runtime_path}.tenantId", f"{runtime_id} must use tenantId writer"))
        runtime_config = runtime.get("config") or {}
        if isinstance(runtime_config, dict):
            for key, expected in expected_config.items():
                actual = str(runtime_config.get(key, "")).strip()
                if actual != expected:
                    findings.append(_finding("error", stack, f"{runtime_path}.config.{key}", f"{runtime_id} must set {key} to {expected!r}"))
            if expected_config["family"] == "cloudtrail" and "start_time" in runtime_config:
                findings.append(_finding("error", stack, f"{runtime_path}.config.start_time", f"{runtime_id} must use rolling since={SEC_DEV_AWS_CLOUDTRAIL_SINCE}, not fixed start_time"))

        if runtime_id not in schedules_by_runtime:
            findings.append(_finding("error", stack, "cerebro:orchestratorSchedules", f"required sec-dev AWS schedule for {runtime_id!r} is missing"))


def validate_stack(path: Path) -> list[Finding]:
    stack = _stack_name(path)
    config = _load_config(path)
    findings: list[Finding] = []

    image_tag = str(config.get("imageTag", "")).strip()
    if not image_tag:
        findings.append(_finding("error", stack, "cerebro:imageTag", "image tag is required"))
    elif _parse_image_tag(image_tag) is None:
        findings.append(_finding("error", stack, "cerebro:imageTag", f"image tag {image_tag!r} must look like vX.Y.Z"))

    api_max_instances = config.get("apiMaxInstances", 1)
    if isinstance(api_max_instances, int) and api_max_instances > 1 and not _supports_cross_task_sync_lock(image_tag):
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:apiMaxInstances",
                "values above 1 require cerebro:imageTag >= v2.1.25",
            )
        )
    if (stack == "sec-dev" or "prod" in str(config.get("environment", stack)).lower() or stack.endswith("prod")) and (
        not isinstance(api_max_instances, int) or api_max_instances < 2
    ):
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:apiMaxInstances",
                "active Cerebro environments must allow at least two API tasks for latency headroom",
            )
        )
    web_max_instances = config.get("webMaxInstances", 1)
    if config.get("webEnabled") is True and (not isinstance(web_max_instances, int) or web_max_instances < 2):
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:webMaxInstances",
                "enabled web consoles must allow at least two tasks for proxy latency headroom",
            )
        )

    alb_access_logs_retention_days = config.get("albAccessLogsRetentionDays", 30)
    if not isinstance(alb_access_logs_retention_days, int) or alb_access_logs_retention_days < 1:
        findings.append(_finding("error", stack, "cerebro:albAccessLogsRetentionDays", "must be a positive integer"))

    for key in ("accessAuditDeniedAlarmThreshold", "accessAuditAuthFailureAlarmThreshold"):
        threshold = config.get(key, 0)
        if not isinstance(threshold, int) or threshold < 0:
            findings.append(_finding("error", stack, f"cerebro:{key}", "must be a non-negative integer"))

    for key in (
        "apiRequestCountPerTargetScalingTarget",
        "apiRequestCountPerTargetAlarmThreshold",
        "apiLatencyP95AlarmThresholdSeconds",
        "webLatencyP95AlarmThresholdSeconds",
        "dashboardLatencyP95AlarmThresholdMs",
    ):
        threshold = config.get(key, 0)
        if not isinstance(threshold, int) or threshold < 0:
            findings.append(_finding("error", stack, f"cerebro:{key}", "must be a non-negative integer"))

    for key in ("accessAuditTenantMismatchAlarmThreshold", "accessAuditSensitiveDeniedAlarmThreshold"):
        threshold = config.get(key, -1)
        if not isinstance(threshold, int) or threshold < -1:
            findings.append(_finding("error", stack, f"cerebro:{key}", "must be an integer greater than or equal to -1"))

    if stack == "sec-dev":
        postgres_instance_class = str(config.get("postgresInstanceClass", "")).strip()
        if not postgres_instance_class or postgres_instance_class.endswith(".micro"):
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:postgresInstanceClass",
                    "sec-dev Postgres instance class must be larger than micro for dashboard query load",
                )
            )

        postgres_allocated_storage = config.get("postgresAllocatedStorage")
        if not isinstance(postgres_allocated_storage, int) or postgres_allocated_storage < 100:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:postgresAllocatedStorage",
                    "sec-dev Postgres allocated storage must be at least 100 GB",
                )
            )

        postgres_max_allocated_storage = config.get("postgresMaxAllocatedStorage")
        if postgres_max_allocated_storage is not None and (
            not isinstance(postgres_max_allocated_storage, int)
            or not isinstance(postgres_allocated_storage, int)
            or postgres_max_allocated_storage < postgres_allocated_storage
        ):
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:postgresMaxAllocatedStorage",
                    "sec-dev Postgres max allocated storage must be greater than or equal to allocated storage",
                )
            )

        postgres_storage_type = str(config.get("postgresStorageType", "")).strip().lower()
        if postgres_storage_type != "gp3":
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:postgresStorageType",
                    "sec-dev Postgres storage type must be gp3",
                )
            )

    alarm_action_arns = config.get("alarmActionArns") or []
    if alarm_action_arns and not isinstance(alarm_action_arns, list):
        findings.append(_finding("error", stack, "cerebro:alarmActionArns", "must be a list"))
        alarm_action_arns = []
    for index, arn in enumerate(alarm_action_arns):
        if not str(arn).strip().startswith("arn:aws:sns:"):
            findings.append(_finding("error", stack, f"cerebro:alarmActionArns[{index}]", "must be an SNS topic ARN"))

    alarm_email_subscriptions = config.get("alarmEmailSubscriptions") or []
    if alarm_email_subscriptions and not isinstance(alarm_email_subscriptions, list):
        findings.append(_finding("error", stack, "cerebro:alarmEmailSubscriptions", "must be a list"))
        alarm_email_subscriptions = []

    source_runtimes = config.get("sourceRuntimes") or []
    if source_runtimes and not isinstance(source_runtimes, list):
        findings.append(_finding("error", stack, "cerebro:sourceRuntimes", "must be a list"))
        source_runtimes = []

    runtime_ids: set[str] = set()
    source_secret_names = _source_secret_names(config.get("sourceSecretKeys") or [])
    s3_role_requirements = _s3_source_role_requirements(config.get("s3Sources") or [])
    for index, runtime in enumerate(source_runtimes):
        runtime_path = f"cerebro:sourceRuntimes[{index}]"
        if not isinstance(runtime, dict):
            findings.append(_finding("error", stack, runtime_path, "runtime entry must be an object"))
            continue

        runtime_id = str(runtime.get("id", "")).strip()
        if not runtime_id:
            findings.append(_finding("error", stack, f"{runtime_path}.id", "runtime id is required"))
        elif runtime_id in runtime_ids:
            findings.append(_finding("error", stack, f"{runtime_path}.id", f"duplicate runtime id {runtime_id!r}"))
        else:
            runtime_ids.add(runtime_id)

        for required_key in ("sourceId", "tenantId", "config"):
            if required_key not in runtime:
                findings.append(_finding("error", stack, f"{runtime_path}.{required_key}", "required key is missing"))

        runtime_config = runtime.get("config") or {}
        if not isinstance(runtime_config, dict):
            findings.append(_finding("error", stack, f"{runtime_path}.config", "runtime config must be an object"))
            continue

        account_id = str(runtime_config.get("account_id", "")).strip()
        role_arn = str(runtime_config.get("role_arn", "")).strip()
        if role_arn:
            match = AWS_ROLE_ARN_RE.match(role_arn)
            if not match:
                findings.append(_finding("error", stack, f"{runtime_path}.config.role_arn", "must be an IAM role ARN"))
            elif str(runtime.get("sourceId", "")).strip() == "aws" and account_id and match.group(2) != account_id:
                findings.append(_finding("error", stack, f"{runtime_path}.config.role_arn", "account must match account_id"))

        runtime_bucket = str(runtime_config.get("bucket", "")).strip()
        runtime_prefix = str(runtime_config.get("prefix", "")).strip()
        for bucket, prefix, required_role_arn in s3_role_requirements:
            if runtime_bucket != bucket or runtime_prefix != prefix:
                continue
            if role_arn != required_role_arn:
                findings.append(
                    _finding(
                        "error",
                        stack,
                        f"{runtime_path}.config.role_arn",
                        f"S3 source runtime for s3://{bucket}/{prefix} must set role_arn to the configured s3Sources roleArn",
                    )
                )

        for env_name, env_path in _env_refs(runtime_config, f"{runtime_path}.config"):
            if not env_name:
                findings.append(_finding("error", stack, env_path, "env reference must include a variable name"))
            elif env_name not in source_secret_names:
                findings.append(
                    _finding(
                        "error",
                        stack,
                        env_path,
                        f"env reference {env_name!r} is not listed in cerebro:sourceSecretKeys",
                    )
                )

        for key, value in runtime_config.items():
            if _is_plain_secret(str(key), value):
                findings.append(
                    _finding(
                        "error",
                        stack,
                        f"{runtime_path}.config.{key}",
                        "secret-like runtime config values must use env: references",
                    )
                )

    schedules = config.get("orchestratorSchedules") or []
    if schedules and not isinstance(schedules, list):
        findings.append(_finding("error", stack, "cerebro:orchestratorSchedules", "must be a list"))
        schedules = []

    scheduled_runtime_ids: set[str] = set()
    top_level_command = config.get("orchestratorCommand")
    top_level_runtime_id = _runtime_id_from_command(top_level_command)
    if top_level_command:
        if top_level_runtime_id is None:
            scheduled_runtime_ids.update(runtime_ids)
        elif top_level_runtime_id not in runtime_ids:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:orchestratorCommand",
                    f"unknown runtime id {top_level_runtime_id!r}",
                )
            )
        else:
            scheduled_runtime_ids.add(top_level_runtime_id)
        guarded_runtime_ids = [top_level_runtime_id] if top_level_runtime_id is not None else sorted(runtime_ids)
        for guarded_runtime_id in guarded_runtime_ids:
            _validate_graph_page_budget(stack, guarded_runtime_id, top_level_command, "cerebro:orchestratorCommand", findings)

    schedule_names: set[str] = set()
    for index, schedule in enumerate(schedules):
        schedule_path = f"cerebro:orchestratorSchedules[{index}]"
        if not isinstance(schedule, dict):
            findings.append(_finding("error", stack, schedule_path, "schedule entry must be an object"))
            continue

        name = str(schedule.get("name", "")).strip()
        if not name:
            findings.append(_finding("error", stack, f"{schedule_path}.name", "schedule name is required"))
        elif name in schedule_names:
            findings.append(_finding("error", stack, f"{schedule_path}.name", f"duplicate schedule name {name!r}"))
        else:
            schedule_names.add(name)

        if not str(schedule.get("scheduleExpression", "")).strip():
            findings.append(_finding("error", stack, f"{schedule_path}.scheduleExpression", "schedule expression is required"))

        task_count = schedule.get("taskCount", 1)
        if not isinstance(task_count, int) or task_count < 1:
            findings.append(_finding("error", stack, f"{schedule_path}.taskCount", "taskCount must be a positive integer"))

        runtime_id = _runtime_id_from_command(schedule.get("command"))
        if runtime_id is None:
            findings.append(_finding("error", stack, f"{schedule_path}.command", "command must include runtime_id=<id>"))
        elif runtime_id not in runtime_ids:
            findings.append(_finding("error", stack, f"{schedule_path}.command", f"unknown runtime id {runtime_id!r}"))
        else:
            scheduled_runtime_ids.add(runtime_id)
            _validate_graph_page_budget(stack, runtime_id, schedule.get("command"), f"{schedule_path}.command", findings)

        if "backfill" in name.lower():
            retirement_key = next((key for key in ("expiresAt", "removeAfter", "expires_after") if key in schedule), "")
            if not retirement_key:
                findings.append(
                    _finding(
                        "warning",
                        stack,
                        f"{schedule_path}.name",
                        "backfill schedules should include expiresAt/removeAfter metadata for retirement",
                    )
                )
            else:
                retirement_date = _parse_retirement_date(schedule.get(retirement_key))
                if retirement_date is None:
                    findings.append(_finding("error", stack, f"{schedule_path}.{retirement_key}", "retirement metadata must be an ISO date"))
                elif retirement_date < datetime.now(UTC):
                    findings.append(_finding("error", stack, f"{schedule_path}.{retirement_key}", "retirement date is in the past"))

    if config.get("orchestratorEnabled", True):
        for runtime_id in sorted(runtime_ids - scheduled_runtime_ids):
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:sourceRuntimes",
                    f"source runtime {runtime_id!r} is not referenced by cerebro:orchestratorCommand or cerebro:orchestratorSchedules",
                )
            )

    _validate_cosmo_gitops(stack, config, source_runtimes, schedules, source_secret_names, findings)
    _validate_sec_dev_aws_coverage(stack, config, source_runtimes, schedules, findings)

    environment = str(config.get("environment", stack)).lower()
    is_prod = stack.endswith("prod") or "prod" in environment
    is_sec_dev = stack == "sec-dev" or environment == "sec-dev"
    postgres_storage_type = str(config.get("postgresStorageType", "gp3")).strip().lower()
    postgres_allocated_storage = config.get("postgresAllocatedStorage")
    postgres_iops = config.get("postgresIops") or None
    postgres_storage_throughput = config.get("postgresStorageThroughput") or None
    if (is_sec_dev or is_prod) and postgres_storage_type == "gp2":
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:postgresStorageType",
                "Postgres storage must not use burst-credit-limited gp2 for active Cerebro environments",
            )
        )
    if (
        postgres_storage_type == "gp3"
        and isinstance(postgres_allocated_storage, int)
        and postgres_allocated_storage < 400
        and (postgres_iops is not None or postgres_storage_throughput is not None)
    ):
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:postgresAllocatedStorage",
                "Postgres gp3 IOPS or throughput overrides require at least 400 GB allocated storage",
            )
        )
    if is_sec_dev:
        if config.get("postgresInstanceClass") == "db.t4g.micro":
            findings.append(_finding("error", stack, "cerebro:postgresInstanceClass", "sec-dev Postgres must not use db.t4g.micro"))
        if isinstance(postgres_allocated_storage, int) and postgres_allocated_storage < 100:
            findings.append(
                _finding("error", stack, "cerebro:postgresAllocatedStorage", "sec-dev Postgres storage must be at least 100 GB")
            )
    if is_prod:
        if config.get("albInternal") is False:
            findings.append(_finding("error", stack, "cerebro:albInternal", "production ALB must remain internal"))
        if config.get("enableWaf") is False:
            findings.append(_finding("error", stack, "cerebro:enableWaf", "production WAF must remain enabled"))
        if config.get("postgresDeletionProtection") is False:
            findings.append(
                _finding("error", stack, "cerebro:postgresDeletionProtection", "production Postgres deletion protection must remain enabled")
            )
        if config.get("apiAuthEnabled") is False:
            findings.append(_finding("error", stack, "cerebro:apiAuthEnabled", "production API auth must remain enabled"))
        if config.get("enableKmsLogEncryption") is False:
            findings.append(_finding("error", stack, "cerebro:enableKmsLogEncryption", "production log encryption must remain enabled"))
        if config.get("enableAlbAccessLogs") is False:
            findings.append(_finding("error", stack, "cerebro:enableAlbAccessLogs", "production ALB access logs must remain enabled"))
        if config.get("enableAlbDeletionProtection") is False:
            findings.append(
                _finding("error", stack, "cerebro:enableAlbDeletionProtection", "production ALB deletion protection must remain enabled")
            )

        backup_retention = config.get("postgresBackupRetentionDays")
        if isinstance(backup_retention, int) and backup_retention < 14:
            findings.append(
                _finding("error", stack, "cerebro:postgresBackupRetentionDays", "production backups must retain at least 14 days")
            )
        if config.get("postgresApplyImmediately") is True:
            findings.append(
                _finding("error", stack, "cerebro:postgresApplyImmediately", "production RDS changes must use the maintenance window")
            )

        allowed_tenants = config.get("allowedTenants") or []
        if not isinstance(allowed_tenants, list) or not allowed_tenants:
            findings.append(_finding("error", stack, "cerebro:allowedTenants", "production must declare allowed tenants"))
        if not alarm_action_arns and not alarm_email_subscriptions:
            findings.append(_finding("error", stack, "cerebro:alarmActionArns", "production alarms must have at least one notification route"))

    return findings


def validate_cross_stack(paths: list[Path]) -> list[Finding]:
    by_stack = {_stack_name(path): _load_config(path) for path in paths}
    findings: list[Finding] = []

    sec_dev = by_stack.get("sec-dev")
    go_prod = by_stack.get("go-prod")
    if sec_dev is not None and go_prod is not None:
        sec_dev_tag = str(sec_dev.get("imageTag", "")).strip()
        go_prod_tag = str(go_prod.get("imageTag", "")).strip()
        sec_dev_parsed = _parse_image_tag(sec_dev_tag)
        go_prod_parsed = _parse_image_tag(go_prod_tag)
        if sec_dev_parsed is not None and go_prod_parsed is not None and sec_dev_parsed < go_prod_parsed:
            findings.append(
                _finding(
                    "error",
                    "sec-dev",
                    "cerebro:imageTag",
                    f"sec-dev image tag {sec_dev_tag} must not lag go-prod {go_prod_tag}",
                )
            )

    return findings


def _default_stack_paths(repo_root: Path) -> list[Path]:
    return sorted((repo_root / "infra" / "aws").glob("Pulumi.*.yaml"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Cerebro AWS Pulumi stack config.")
    parser.add_argument("paths", nargs="*", type=Path, help="Stack YAML files to validate.")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--strict-warnings", action="store_true", help="Treat warnings as failures.")
    args = parser.parse_args(argv)

    paths = args.paths or _default_stack_paths(args.repo_root)
    findings: list[Finding] = []
    for path in paths:
        findings.extend(validate_stack(path))
    findings.extend(validate_cross_stack(paths))

    for finding in findings:
        print(f"{finding.severity.upper()}: {finding.stack} {finding.path}: {finding.message}")

    has_error = any(finding.severity == "error" for finding in findings)
    has_warning = any(finding.severity == "warning" for finding in findings)
    return 1 if has_error or (args.strict_warnings and has_warning) else 0


if __name__ == "__main__":
    sys.exit(main())
