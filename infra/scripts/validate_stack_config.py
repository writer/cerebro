#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import math
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

UTC = timezone.utc

try:
    from aws import source_runtime_scope
    from aws.source_rollouts import SourceRuntimeRolloutError, apply_source_runtime_rollouts
except ModuleNotFoundError:  # pragma: no cover - used when executed as scripts/validate_stack_config.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from aws import source_runtime_scope
    from aws.source_rollouts import SourceRuntimeRolloutError, apply_source_runtime_rollouts


MIN_CROSS_TASK_SYNC_LOCK_VERSION = (2, 1, 25)
MIN_COSMO_TOKEN_AUTH_VERSION = (2, 1, 36)
MIN_AWS_EFFECTIVE_PERMISSION_VERSION = (2, 1, 46)
IMAGE_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$")
SECRET_KEY_RE = re.compile(r"(secret|token|password|api_?key|client_secret|private_key)", re.IGNORECASE)
AWS_ROLE_ARN_RE = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$")
AWS_REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")
BEDROCK_MODEL_ID_RE = re.compile(r"^(?:[a-z]+\.)?anthropic\.claude-[A-Za-z0-9.-]+(?::[0-9]+)?$")
BEDROCK_MODEL_ARN_RE = re.compile(r"^arn:aws:bedrock:[a-z0-9-]+:(?:(?:[0-9]{12})?):(?:foundation-model|inference-profile)/[A-Za-z0-9_.:-]+$")
EVENTBRIDGE_RULE_NAME_MAX_LENGTH = 64
EVENTBRIDGE_RULES_PER_BUS_DEFAULT_QUOTA = 300
RESERVED_EVENTBRIDGE_RULES_BY_STACK = {
    "go-prod": 6,
}
COSMO_REQUIRED_STACKS = {"sec-dev"}
COSMO_REQUIRED_SECRETS = {"CEREBRO_SOURCE_COSMO_BASE_URL", "CEREBRO_SOURCE_COSMO_TOKEN"}
COSMO_MESSAGE_EXPORT_SECRET = "CEREBRO_SOURCE_COSMO_EXPORT_SECRET"
COSMO_RUNTIME_FAMILIES = {
    "writer-cosmo-session": "session",
    "writer-cosmo-fact": "fact",
    "writer-cosmo-survey-feedback": "survey_feedback",
}
COSMO_OPTIONAL_RUNTIME_FAMILIES = {
    "writer-cosmo-message": "message",
}
COSMO_GRAPH_BUDGETED_RUNTIMES = {"writer-cosmo-session", "writer-cosmo-fact"}
TEMPORARILY_DISABLEABLE_SOURCE_RUNTIMES = set(COSMO_RUNTIME_FAMILIES) | set(COSMO_OPTIONAL_RUNTIME_FAMILIES)


class QuarantineReason(str, Enum):
    INVALID_CREDENTIALS = "invalid_credentials"
    MISSING_SECRET = "missing_secret"
    UPSTREAM_AUTH_FAILURE = "upstream_auth_failure"
    UPSTREAM_RATE_LIMIT = "upstream_rate_limit"
    UPSTREAM_SCHEMA_DRIFT = "upstream_schema_drift"
    RUNTIME_CONTRACT_MISMATCH = "runtime_contract_mismatch"
    BOOTSTRAP_PAYLOAD_STALE = "bootstrap_payload_stale"
    TASK_FAILURE = "task_failure"
    GRAPH_INGEST_FAILURE = "graph_ingest_failure"
    MANUAL_OPERATOR_ACTION = "manual_operator_action"


class SourceRuntimeLifecycleState(str, Enum):
    ACTIVE = "active"
    READINESS_ONLY = "readiness_only"
    QUARANTINED = "quarantined"
    DEPRECATED = "deprecated"


QUARANTINE_REASONS = {reason.value for reason in QuarantineReason}
QUARANTINE_REQUIRED_FIELDS = {"runtimeId", "owner", "reason", "disabledDate", "reviewDeadline", "reenableCriteria"}
SOURCE_RUNTIME_LIFECYCLE_STATES = {state.value for state in SourceRuntimeLifecycleState}
COSMO_MAX_GRAPH_BUDGET_PAGE_LIMIT = 5
COSMO_MAX_GRAPH_BUDGET_GRAPH_PAGE_LIMIT = 5
COSMO_MAX_GRAPH_BUDGET_EVENT_LIMIT = 500
SEC_DEV_HIGH_CONTENTION_GRAPH_RUNTIMES = {
    "writer-aws-sec-dev-us1-asset-metadata",
    "writer-aws-sec-dev-us1-cloudtrail",
    "writer-aws-sec-dev-us2-asset-metadata",
    "writer-aws-sec-dev-us2-cloudtrail",
    "writer-aurelius-image-scans",
    "writer-github-audit",
    "writer-github-audit-writerinternal",
    "writer-gcp-dev-devops-asset-metadata",
    "writer-gcp-dev-devops-audit",
    "writer-gcp-dev-networking-asset-metadata",
    "writer-gcp-dev-networking-audit",
    "writer-gcp-dev-qordoba-devel-asset-metadata",
    "writer-gcp-dev-qordoba-devel-audit",
    "writer-gcp-dev-writer-iam-asset-metadata",
    "writer-gcp-dev-writer-iam-audit",
    "writer-okta-audit",
    "writer-okta-audit-2026-04",
    "writer-okta-audit-2026-q1",
    "writer-panopticon-alerts",
    "writer-panopticon-cases",
    "writer-panopticon-iocs",
    "writer-sentinelone-application",
    "writer-aurelius-findings",
    "writer-aurelius-verdicts",
}
SEC_DEV_MAX_HIGH_CONTENTION_PAGE_LIMIT = 5
SEC_DEV_MAX_HIGH_CONTENTION_GRAPH_PAGE_LIMIT = 5
SEC_DEV_STRICT_GRAPH_RUNTIMES = {
    "writer-aurelius-findings",
}
SEC_DEV_MAX_STRICT_PAGE_LIMIT = 1
SEC_DEV_MAX_STRICT_GRAPH_PAGE_LIMIT = 1
PROD_HIGH_CONTENTION_GRAPH_RUNTIMES = {
    "writer-grc-vulnerable-asset",
    "writer-vulnview-dns-alert",
    "writer-vulnview-vulnerability",
}
PROD_MAX_HIGH_CONTENTION_PAGE_LIMIT = 1
PROD_MAX_HIGH_CONTENTION_GRAPH_PAGE_LIMIT = 1
ACTIVE_JETSTREAM_MIN_PUBLISH_MAX_IN_FLIGHT = 4
ACTIVE_JETSTREAM_MIN_PUBLISH_RETRY_MAX_ELAPSED_SECONDS = 300
ACTIVE_NATS_MIN_MEMORY_MIB = 32768
SEC_DEV_AWS_ACCOUNT_ID = "944130631940"
SEC_DEV_AWS_ROLE_ARN = "arn:aws:iam::944130631940:role/cerebro-org-scan-role"
AWS_CLOUD_DEPTH_GLOBAL_FAMILIES = {
    "organizations_account",
    "organizations_policy",
}
AWS_CLOUD_DEPTH_REGIONAL_FAMILIES = {
    "guardduty_finding",
    "inspector2_finding",
    "kms_key",
    "rds_instance",
    "route_table",
    "s3_bucket",
    "secret",
    "security_group",
    "securityhub_finding",
    "subnet",
    "vpc",
    "vpc_endpoint",
}
SEC_DEV_AWS_GLOBAL_FAMILIES = {
    "access_key",
    "effective_permission",
    "iam_group",
    "iam_group_membership",
    "iam_role",
    "iam_role_assignment",
    "iam_role_trust",
    "iam_user",
    *AWS_CLOUD_DEPTH_GLOBAL_FAMILIES,
}
AWS_COMPUTE_REGIONAL_FAMILIES = {
    "ec2_instance",
    "ecs_service",
    "ecs_task",
    "ecs_task_definition",
    "eks_cluster",
    "eks_fargate_profile",
    "eks_nodegroup",
    "eks_pod_identity_association",
    "lambda_function",
}
SEC_DEV_AWS_REGIONAL_FAMILIES = {
    "asset_metadata",
    "cloudtrail",
    "public_endpoint",
    "resource_exposure",
    *AWS_COMPUTE_REGIONAL_FAMILIES,
    *AWS_CLOUD_DEPTH_REGIONAL_FAMILIES,
}
SEC_DEV_AWS_CLOUDTRAIL_SINCE = "PT15M"
GO_PROD_AWS_ACCOUNTS = {
    "sec-prod": "837279440628",
    "prod": "009160076449",
    "devops": "381491964434",
    "sec-dev": "944130631940",
}
GO_PROD_AWS_GLOBAL_FAMILIES = SEC_DEV_AWS_GLOBAL_FAMILIES
GO_PROD_AWS_REGIONAL_FAMILIES = {
    "asset_metadata",
    "public_endpoint",
    "resource_exposure",
    *AWS_COMPUTE_REGIONAL_FAMILIES,
    *AWS_CLOUD_DEPTH_REGIONAL_FAMILIES,
}
GO_PROD_AWS_REGIONS = {"us1": "us-east-1", "us2": "us-west-2"}
PANOPTICON_RUNTIME_FAMILIES = {
    "writer-panopticon-alerts": "alert",
    "writer-panopticon-cases": "case",
    "writer-panopticon-iocs": "ioc",
}
PANOPTICON_STACKS = {"sec-dev", "go-prod"}
PANOPTICON_SOURCE_SECRET_KEYS = {
    "base_url": "env:CEREBRO_SOURCE_PANOPTICON_BASE_URL",
    "private_endpoint_allowlist": "env:CEREBRO_SOURCE_PANOPTICON_PRIVATE_ENDPOINT_ALLOWLIST",
    "token": "env:CEREBRO_SOURCE_PANOPTICON_TOKEN",
}
PANOPTICON_RUNTIME_CONFIG_KEYS = {
    "base_url",
    "family",
    "mode",
    "page_size",
    "private_endpoint_allowlist",
    "runtime_id",
    "tenant_id",
    "token",
}
PANOPTICON_FORBIDDEN_CONFIG_RE = re.compile(
    r"(evidence_?bytes|evidence_?content|file_?contents?|payload_?bytes|plaintext|secret|token|password|private_?key)",
    re.IGNORECASE,
)
OBSERVABILITY_STATUS_MODEL = ["success", "failure", "stale", "disabled", "unknown", "not_configured"]
OBSERVABILITY_SOURCE_SYSTEMS = {"evidence_cas", "okta", "panopticon"}
OTEL_EXPORTER_PROTOCOLS = {"http/protobuf", "grpc"}
NEO4J_GENERATED_RUNTIME_SECRET_KEYS = {
    "CEREBRO_NEO4J_URI",
    "CEREBRO_NEO4J_USERNAME",
    "CEREBRO_NEO4J_PASSWORD",
    "CEREBRO_API_KEYS",
    "CEREBRO_API_CREDENTIALS_JSON",
}
OBSERVABILITY_REQUIRED_KEYS = {
    "environment",
    "sourceSystem",
    "sourceRuntimeId",
    "runtimeClass",
    "enabled",
    "freshnessSlaMinutes",
    "logGroupRef",
    "dashboardEnabled",
    "alarmEnabled",
    "alarmRoute",
    "observabilityStates",
}
OBSERVABILITY_REQUIRED_RUNTIME_KEYS = {
    "sec-dev": {
        ("evidence_cas", "writer-evidence-cas-cases", "object"): True,
        ("panopticon", "writer-panopticon-alerts", "alert"): True,
        ("panopticon", "writer-panopticon-cases", "case"): True,
        ("panopticon", "writer-panopticon-iocs", "ioc"): True,
    },
    "go-prod": {
        ("evidence_cas", "writer-evidence-cas-cases", "object"): False,
        ("panopticon", "writer-panopticon-alerts", "alert"): True,
        ("panopticon", "writer-panopticon-cases", "case"): True,
        ("panopticon", "writer-panopticon-iocs", "ioc"): True,
    },
}
OKTA_OBSERVABILITY_RUNTIME_CLASSES = {
    "writer-okta-audit": "audit",
    "writer-okta-application": "application",
    "writer-okta-dept-security-group-membership": "group_membership",
    "writer-okta-group": "group",
    "writer-okta-user": "user",
}


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
    return source_runtime_scope.env_refs(value, path)


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


def _string_set(values: Any) -> set[str]:
    if not isinstance(values, list):
        return set()
    return {str(value).strip() for value in values if str(value).strip()}


def _parse_date(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00") if len(text) != 10 else f"{text}T00:00:00+00:00")
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed
    except ValueError:
        return None


def _parse_duration_seconds(value: Any) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ns|us|µs|ms|s|m|h)", text)
    if not match:
        return None
    amount = float(match.group(1))
    multiplier = {
        "ns": 1 / 1_000_000_000,
        "us": 1 / 1_000_000,
        "µs": 1 / 1_000_000,
        "ms": 1 / 1_000,
        "s": 1,
        "m": 60,
        "h": 3600,
    }[match.group(2)]
    return amount * multiplier


def _quarantined_source_runtime_ids(stack: str, config: dict[str, Any], findings: list[Finding]) -> set[str]:
    entries = config.get("temporarilyDisabledSourceRuntimes") or []
    if not isinstance(entries, list):
        findings.append(_finding("error", stack, "cerebro:temporarilyDisabledSourceRuntimes", "must be a list"))
        return set()

    runtime_ids: set[str] = set()
    for index, entry in enumerate(entries):
        path = f"cerebro:temporarilyDisabledSourceRuntimes[{index}]"
        if not isinstance(entry, dict):
            findings.append(_finding("error", stack, path, "quarantined runtime entry must be an object with metadata"))
            continue

        missing = sorted(field for field in QUARANTINE_REQUIRED_FIELDS if field not in entry)
        if missing:
            findings.append(_finding("error", stack, path, f"quarantined runtime entry is missing required field(s): {', '.join(missing)}"))

        runtime_id = str(entry.get("runtimeId", "")).strip()
        if not runtime_id:
            findings.append(_finding("error", stack, f"{path}.runtimeId", "runtimeId is required"))
        else:
            runtime_ids.add(runtime_id)

        owner = str(entry.get("owner", "")).strip()
        if not owner:
            findings.append(_finding("error", stack, f"{path}.owner", "owner is required"))

        reason = str(entry.get("reason", "")).strip()
        if not reason:
            findings.append(_finding("error", stack, f"{path}.reason", "reason is required"))
        elif reason not in QUARANTINE_REASONS:
            findings.append(
                _finding(
                    "error",
                    stack,
                    f"{path}.reason",
                    f"reason must be one of: {', '.join(sorted(QUARANTINE_REASONS))}",
                )
            )

        disabled_date = _parse_date(entry.get("disabledDate"))
        if disabled_date is None:
            findings.append(_finding("error", stack, f"{path}.disabledDate", "disabledDate must be an ISO date"))

        review_deadline = _parse_date(entry.get("reviewDeadline"))
        if review_deadline is None:
            findings.append(_finding("error", stack, f"{path}.reviewDeadline", "reviewDeadline must be an ISO date"))
        elif review_deadline < datetime.now(UTC):
            findings.append(_finding("warning", stack, f"{path}.reviewDeadline", "reviewDeadline has passed; review the runtime quarantine"))

        if disabled_date is not None and review_deadline is not None and review_deadline < disabled_date:
            findings.append(_finding("error", stack, f"{path}.reviewDeadline", "reviewDeadline must be on or after disabledDate"))

        reenable_criteria = entry.get("reenableCriteria")
        if isinstance(reenable_criteria, str):
            if not reenable_criteria.strip():
                findings.append(_finding("error", stack, f"{path}.reenableCriteria", "reenableCriteria must be non-empty"))
        elif isinstance(reenable_criteria, list):
            if not reenable_criteria or not all(isinstance(value, str) and value.strip() for value in reenable_criteria):
                findings.append(_finding("error", stack, f"{path}.reenableCriteria", "reenableCriteria list items must be non-empty strings"))
        else:
            findings.append(_finding("error", stack, f"{path}.reenableCriteria", "reenableCriteria must be a string or a list of strings"))

        lifecycle_state = str(entry.get("lifecycleState") or SourceRuntimeLifecycleState.QUARANTINED.value).strip()
        if lifecycle_state not in SOURCE_RUNTIME_LIFECYCLE_STATES:
            findings.append(
                _finding(
                    "error",
                    stack,
                    f"{path}.lifecycleState",
                    f"lifecycleState must be one of: {', '.join(sorted(SOURCE_RUNTIME_LIFECYCLE_STATES))}",
                )
            )
        elif lifecycle_state != SourceRuntimeLifecycleState.QUARANTINED.value:
            findings.append(_finding("error", stack, f"{path}.lifecycleState", "temporary runtime metadata must use lifecycleState quarantined"))

    return runtime_ids


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


def _schedule_suffix(value: Any) -> str:
    chars = []
    for char in str(value).strip().lower():
        if ("a" <= char <= "z") or ("0" <= char <= "9"):
            chars.append(char)
        elif chars and chars[-1] != "-":
            chars.append("-")
    return "".join(chars).strip("-")


def _orchestrator_rule_name(environment: str, schedule_name: str) -> str:
    return f"cerebro-{environment}-orchestrator-{_schedule_suffix(schedule_name)}"


def _orchestrator_schedule_limit(stack: str) -> int | None:
    reserved_rules = RESERVED_EVENTBRIDGE_RULES_BY_STACK.get(stack)
    if reserved_rules is None:
        return None
    return EVENTBRIDGE_RULES_PER_BUS_DEFAULT_QUOTA - reserved_rules


def _schedule_backend(schedule: dict[str, Any]) -> str:
    return str(schedule.get("backend") or schedule.get("scheduleBackend") or "eventbridge").strip()


def _schedule_state(schedule: dict[str, Any]) -> str:
    return str(schedule.get("state") or schedule.get("scheduleState") or "ENABLED").strip().upper()


def _validate_source_runtime_service_bootstrap(
    stack: str,
    config: dict[str, Any],
    source_runtimes: list[Any],
    runtime_ids: set[str],
    findings: list[Finding],
) -> None:
    if not source_runtimes:
        return
    bootstrap_ids = config.get("sourceRuntimeServiceBootstrapIds")
    if bootstrap_ids is not None and not isinstance(bootstrap_ids, list):
        findings.append(_finding("error", stack, "cerebro:sourceRuntimeServiceBootstrapIds", "must be a list"))
        return
    if isinstance(bootstrap_ids, list):
        requested_ids = [str(runtime_id).strip() for runtime_id in bootstrap_ids]
        for index, runtime_id in enumerate(requested_ids):
            if not runtime_id:
                findings.append(_finding("error", stack, f"cerebro:sourceRuntimeServiceBootstrapIds[{index}]", "runtime id must be non-empty"))
            elif runtime_id not in runtime_ids:
                findings.append(_finding("error", stack, f"cerebro:sourceRuntimeServiceBootstrapIds[{index}]", f"unknown runtime id {runtime_id!r}"))


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


def _plain_secret_paths(value: Any, path: str) -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if _is_plain_secret(str(key), child):
                findings.append(child_path)
            findings.extend(_plain_secret_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(_plain_secret_paths(child, f"{path}[{index}]"))
    return findings


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
    if stack == "sec-dev" and runtime_id in SEC_DEV_STRICT_GRAPH_RUNTIMES:
        max_page_limit = SEC_DEV_MAX_STRICT_PAGE_LIMIT
        max_graph_page_limit = SEC_DEV_MAX_STRICT_GRAPH_PAGE_LIMIT
    elif stack == "sec-dev" and runtime_id in SEC_DEV_HIGH_CONTENTION_GRAPH_RUNTIMES:
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
    disabled_runtime_ids: set[str],
    findings: list[Finding],
) -> None:
    unknown_disabled_runtime_ids = disabled_runtime_ids - TEMPORARILY_DISABLEABLE_SOURCE_RUNTIMES
    if unknown_disabled_runtime_ids:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:temporarilyDisabledSourceRuntimes",
                f"unsupported temporary runtime bypasses: {', '.join(sorted(unknown_disabled_runtime_ids))}",
            )
        )

    runtimes_by_id: dict[str, tuple[int, dict[str, Any]]] = {}
    for index, runtime in enumerate(source_runtimes):
        if isinstance(runtime, dict):
            runtime_id = str(runtime.get("id", "")).strip()
            if runtime_id:
                runtimes_by_id[runtime_id] = (index, runtime)

    managed_stack = stack in COSMO_REQUIRED_STACKS or any(runtime_id in runtimes_by_id for runtime_id in COSMO_RUNTIME_FAMILIES)
    cosmo_runtime_families = dict(COSMO_RUNTIME_FAMILIES) if managed_stack else {}
    for runtime_id in disabled_runtime_ids:
        cosmo_runtime_families.pop(runtime_id, None)
    if COSMO_MESSAGE_EXPORT_SECRET in source_secret_names or any(
        runtime_id in runtimes_by_id for runtime_id in COSMO_OPTIONAL_RUNTIME_FAMILIES
    ):
        cosmo_runtime_families.update({
            runtime_id: family
            for runtime_id, family in COSMO_OPTIONAL_RUNTIME_FAMILIES.items()
            if runtime_id not in disabled_runtime_ids
        })
        if COSMO_MESSAGE_EXPORT_SECRET not in source_secret_names:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:sourceSecretKeys",
                    f"Cosmo message secret {COSMO_MESSAGE_EXPORT_SECRET!r} must be declared when the message runtime is configured",
                )
            )

    if not managed_stack and not cosmo_runtime_families:
        return

    if managed_stack:
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

    schedules_by_runtime: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, schedule in enumerate(schedules):
        if isinstance(schedule, dict):
            runtime_id = _runtime_id_from_command(schedule.get("command"))
            if runtime_id:
                schedules_by_runtime.setdefault(runtime_id, []).append((index, schedule))

    for runtime_id, family in cosmo_runtime_families.items():
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
            if stack == "sec-dev" and runtime_id in COSMO_GRAPH_BUDGETED_RUNTIMES:
                command = schedule.get("command")
                page_limit = _uint_arg_from_command(command, "page_limit")
                graph_page_limit = _uint_arg_from_command(command, "graph_page_limit")
                event_limit = _uint_arg_from_command(command, "event_limit")
                if page_limit is None or page_limit > COSMO_MAX_GRAPH_BUDGET_PAGE_LIMIT:
                    findings.append(
                        _finding(
                            "error",
                            stack,
                            f"{schedule_path}.command",
                            f"{runtime_id} must set page_limit <= {COSMO_MAX_GRAPH_BUDGET_PAGE_LIMIT}",
                        )
                    )
                if graph_page_limit is None or graph_page_limit > COSMO_MAX_GRAPH_BUDGET_GRAPH_PAGE_LIMIT:
                    findings.append(
                        _finding(
                            "error",
                            stack,
                            f"{schedule_path}.command",
                            f"{runtime_id} must set graph_page_limit <= {COSMO_MAX_GRAPH_BUDGET_GRAPH_PAGE_LIMIT}",
                        )
                    )
                if event_limit is None or event_limit > COSMO_MAX_GRAPH_BUDGET_EVENT_LIMIT:
                    findings.append(
                        _finding(
                            "error",
                            stack,
                            f"{schedule_path}.command",
                            f"{runtime_id} must set event_limit <= {COSMO_MAX_GRAPH_BUDGET_EVENT_LIMIT}",
                        )
                    )


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


def _validate_go_prod_aws_coverage(
    stack: str,
    source_runtimes: list[Any],
    schedules: list[Any],
    findings: list[Finding],
) -> None:
    if stack != "go-prod":
        return

    runtime_entries: dict[str, tuple[int, dict[str, Any]]] = {}
    has_aws_public_endpoint = False
    for index, runtime in enumerate(source_runtimes):
        if not isinstance(runtime, dict):
            continue
        runtime_id = str(runtime.get("id", "")).strip()
        if runtime_id:
            runtime_entries[runtime_id] = (index, runtime)
        if str(runtime.get("sourceId", "")).strip() != "aws":
            continue
        runtime_config = runtime.get("config") or {}
        if isinstance(runtime_config, dict) and str(runtime_config.get("family", "")).strip() == "public_endpoint":
            has_aws_public_endpoint = True

    if not has_aws_public_endpoint:
        return

    schedules_by_runtime: dict[str, list[int]] = {}
    for index, schedule in enumerate(schedules):
        if isinstance(schedule, dict):
            runtime_id = _runtime_id_from_command(schedule.get("command"))
            if runtime_id:
                schedules_by_runtime.setdefault(runtime_id, []).append(index)

    required: dict[str, dict[str, str]] = {}
    for account_slug, account_id in sorted(GO_PROD_AWS_ACCOUNTS.items()):
        role_arn = f"arn:aws:iam::{account_id}:role/cerebro-org-scan-role"
        for family in sorted(GO_PROD_AWS_GLOBAL_FAMILIES):
            required[f"writer-aws-{account_slug}-{family.replace('_', '-')}"] = {
                "account_id": account_id,
                "family": family,
                "include_global": "true",
                "region": "us-east-1",
                "role_arn": role_arn,
            }
        for region_slug, region in sorted(GO_PROD_AWS_REGIONS.items()):
            for family in sorted(GO_PROD_AWS_REGIONAL_FAMILIES):
                required[f"writer-aws-{account_slug}-{region_slug}-{family.replace('_', '-')}"] = {
                    "account_id": account_id,
                    "family": family,
                    "include_global": "true" if region == "us-east-1" else "false",
                    "per_page": "100",
                    "region": region,
                    "role_arn": role_arn,
                }

    for runtime_id, expected_config in sorted(required.items()):
        runtime_entry = runtime_entries.get(runtime_id)
        if runtime_entry is None:
            findings.append(_finding("error", stack, "cerebro:sourceRuntimes", f"required go-prod AWS coverage runtime {runtime_id!r} is missing"))
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

        if runtime_id not in schedules_by_runtime:
            findings.append(_finding("error", stack, "cerebro:orchestratorSchedules", f"required go-prod AWS schedule for {runtime_id!r} is missing"))


def _normalize_s3_prefix(value: Any) -> str:
    text = str(value or "").strip().lstrip("/")
    return text if not text or text.endswith("/") else f"{text}/"


def _panopticon_runtime_id_from_schedule(schedule: Any) -> str | None:
    runtime_id = _runtime_id_from_command(schedule.get("command") if isinstance(schedule, dict) else None)
    if runtime_id in PANOPTICON_RUNTIME_FAMILIES:
        return runtime_id
    return None


def _validate_panopticon_wiring(
    stack: str,
    config: dict[str, Any],
    source_runtimes: list[Any],
    schedules: list[Any],
    findings: list[Finding],
) -> None:
    if stack not in PANOPTICON_STACKS:
        return

    s3_sources = config.get("s3Sources") or []
    if not isinstance(s3_sources, list):
        findings.append(_finding("error", stack, "cerebro:s3Sources", "s3Sources must be a list"))
        s3_sources = []

    panopticon_sources = [
        (index, source)
        for index, source in enumerate(s3_sources)
        if isinstance(source, dict) and str(source.get("name", "")).strip() == "panopticon"
    ]
    if panopticon_sources:
        findings.append(
            _finding(
                "error",
                stack,
                f"cerebro:s3Sources[{panopticon_sources[0][0]}]",
                "Panopticon API mode must not declare an s3Sources entry named 'panopticon'",
            )
        )

    runtimes_by_id = {
        str(runtime.get("id", "")).strip(): (index, runtime)
        for index, runtime in enumerate(source_runtimes)
        if isinstance(runtime, dict)
    }
    for runtime_id, family in PANOPTICON_RUNTIME_FAMILIES.items():
        runtime_entry = runtimes_by_id.get(runtime_id)
        if runtime_entry is None:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:sourceRuntimes",
                    f"required Panopticon runtime {runtime_id!r} is missing",
                )
            )
            continue

        runtime_index, runtime = runtime_entry
        runtime_path = f"cerebro:sourceRuntimes[{runtime_index}]"
        if str(runtime.get("sourceId", "")).strip() != "panopticon":
            findings.append(_finding("error", stack, f"{runtime_path}.sourceId", "Panopticon runtime sourceId must be 'panopticon'"))
        if str(runtime.get("tenantId", "")).strip() != "writer":
            findings.append(_finding("error", stack, f"{runtime_path}.tenantId", "Panopticon runtime tenantId must be 'writer'"))

        runtime_config = runtime.get("config") or {}
        if not isinstance(runtime_config, dict):
            findings.append(_finding("error", stack, f"{runtime_path}.config", "Panopticon runtime config must be an object"))
            continue

        extra_keys = sorted(set(str(key) for key in runtime_config) - PANOPTICON_RUNTIME_CONFIG_KEYS)
        if extra_keys:
            findings.append(
                _finding(
                    "error",
                    stack,
                    f"{runtime_path}.config",
                    f"Panopticon runtime config contains unsupported keys {extra_keys!r}",
                )
            )
        for key, value in runtime_config.items():
            if key in PANOPTICON_SOURCE_SECRET_KEYS:
                expected_ref = PANOPTICON_SOURCE_SECRET_KEYS[key]
                if str(value or "").strip() != expected_ref:
                    findings.append(
                        _finding(
                            "error",
                            stack,
                            f"{runtime_path}.config.{key}",
                            f"Panopticon API runtime {key} must be {expected_ref!r}",
                        )
                    )
                continue
            if PANOPTICON_FORBIDDEN_CONFIG_RE.search(str(key)) or (
                isinstance(value, str) and PANOPTICON_FORBIDDEN_CONFIG_RE.search(value)
            ):
                findings.append(
                    _finding(
                        "error",
                        stack,
                        f"{runtime_path}.config.{key}",
                        "Panopticon runtime config must not include secrets, tokens, or evidence bytes",
                    )
                )
            if isinstance(value, str) and value.strip().startswith("env:"):
                findings.append(
                    _finding(
                        "error",
                        stack,
                        f"{runtime_path}.config.{key}",
                        "Panopticon API runtime config must only use env references for base_url, private_endpoint_allowlist, and token",
                    )
                )

        expected_runtime_config = {
            "base_url": PANOPTICON_SOURCE_SECRET_KEYS["base_url"],
            "family": family,
            "mode": "api",
            "page_size": "100",
            "private_endpoint_allowlist": PANOPTICON_SOURCE_SECRET_KEYS["private_endpoint_allowlist"],
            "runtime_id": runtime_id,
            "tenant_id": "writer",
            "token": PANOPTICON_SOURCE_SECRET_KEYS["token"],
        }
        for key, expected_value in expected_runtime_config.items():
            actual_text = str(runtime_config.get(key) or "").strip()
            expected_text = expected_value
            if actual_text != expected_text:
                findings.append(
                    _finding(
                        "error",
                        stack,
                        f"{runtime_path}.config.{key}",
                        f"Panopticon {family} API runtime {key} must be {expected_text!r}",
                    )
                )

    schedules_by_runtime: dict[str, list[tuple[int, dict[str, Any]]]] = {runtime_id: [] for runtime_id in PANOPTICON_RUNTIME_FAMILIES}
    for index, schedule in enumerate(schedules):
        runtime_id = _panopticon_runtime_id_from_schedule(schedule)
        if runtime_id:
            schedules_by_runtime[runtime_id].append((index, schedule))

    for runtime_id in PANOPTICON_RUNTIME_FAMILIES:
        runtime_schedules = schedules_by_runtime[runtime_id]
        if len(runtime_schedules) != 1:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:orchestratorSchedules",
                    f"Panopticon runtime {runtime_id!r} must have exactly one schedule",
                )
            )
            continue
        schedule_index, schedule = runtime_schedules[0]
        schedule_path = f"cerebro:orchestratorSchedules[{schedule_index}]"
        if schedule.get("taskCount") != 1:
            findings.append(_finding("error", stack, f"{schedule_path}.taskCount", "Panopticon schedules must set taskCount: 1"))
        command = schedule.get("command") or []
        if not isinstance(command, list) or command[:2] != ["orchestrator", "run"]:
            findings.append(_finding("error", stack, f"{schedule_path}.command", "Panopticon schedule command must run the orchestrator"))


def _validate_source_runtime_observability(
    stack: str,
    config: dict[str, Any],
    source_runtimes: list[Any],
    findings: list[Finding],
) -> None:
    expected_entries = dict(OBSERVABILITY_REQUIRED_RUNTIME_KEYS.get(stack) or {})
    if stack in {"sec-dev", "go-prod"}:
        for runtime in source_runtimes:
            if not isinstance(runtime, dict) or str(runtime.get("sourceId", "")).strip() != "okta":
                continue
            runtime_id = str(runtime.get("id", "")).strip()
            expected_family = OKTA_OBSERVABILITY_RUNTIME_CLASSES.get(runtime_id)
            runtime_config = runtime.get("config") or {}
            actual_family = str(runtime_config.get("family", "")).strip() if isinstance(runtime_config, dict) else ""
            if expected_family and actual_family == expected_family:
                expected_entries[("okta", runtime_id, expected_family)] = True
    if not expected_entries:
        return

    observability_entries = config.get("sourceRuntimeObservability")
    if not isinstance(observability_entries, list) or not observability_entries:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:sourceRuntimeObservability",
                "source runtime observability must explicitly declare required source monitoring entries",
            )
        )
        return

    runtimes_by_id = {
        str(runtime.get("id", "")).strip(): runtime
        for runtime in source_runtimes
        if isinstance(runtime, dict) and str(runtime.get("id", "")).strip()
    }
    seen: set[tuple[str, str, str]] = set()
    expected_environment = str(config.get("environment", stack)).strip()

    for index, entry in enumerate(observability_entries):
        path = f"cerebro:sourceRuntimeObservability[{index}]"
        if not isinstance(entry, dict):
            findings.append(_finding("error", stack, path, "source runtime observability entry must be an object"))
            continue

        for key in sorted(OBSERVABILITY_REQUIRED_KEYS):
            if key not in entry:
                findings.append(
                    _finding(
                        "error",
                        stack,
                        f"{path}.{key}",
                        "source runtime observability entry is missing a required field",
                    )
                )

        environment = str(entry.get("environment", "")).strip()
        source_system = str(entry.get("sourceSystem", "")).strip()
        runtime_id = str(entry.get("sourceRuntimeId", "")).strip()
        runtime_class = str(entry.get("runtimeClass", "")).strip()
        key = (source_system, runtime_id, runtime_class)
        if all(key):
            if key in seen:
                findings.append(_finding("error", stack, f"{path}.sourceRuntimeId", "duplicate source runtime observability entry"))
            seen.add(key)

        if environment != expected_environment:
            findings.append(
                _finding(
                    "error",
                    stack,
                    f"{path}.environment",
                    f"source runtime observability environment must match stack environment {expected_environment!r}",
                )
            )
        if source_system not in OBSERVABILITY_SOURCE_SYSTEMS:
            findings.append(
                _finding(
                    "error",
                    stack,
                    f"{path}.sourceSystem",
                    f"source runtime observability sourceSystem must be one of {', '.join(sorted(OBSERVABILITY_SOURCE_SYSTEMS))}",
                )
            )
        enabled = entry.get("enabled")
        if not isinstance(enabled, bool):
            findings.append(_finding("error", stack, f"{path}.enabled", "source runtime observability enabled state must be boolean"))
            enabled = False
        if not isinstance(entry.get("dashboardEnabled"), bool):
            findings.append(_finding("error", stack, f"{path}.dashboardEnabled", "dashboard participation must be boolean"))
        if not isinstance(entry.get("alarmEnabled"), bool):
            findings.append(_finding("error", stack, f"{path}.alarmEnabled", "alarm participation must be boolean"))
        if str(entry.get("logGroupRef", "")).strip() != "runtime":
            findings.append(_finding("error", stack, f"{path}.logGroupRef", "source runtime observability log group reference must be 'runtime'"))
        if str(entry.get("alarmRoute", "")).strip() != "default":
            findings.append(_finding("error", stack, f"{path}.alarmRoute", "source runtime observability alarmRoute must use the default stack route"))

        freshness_sla_minutes = entry.get("freshnessSlaMinutes")
        if not isinstance(freshness_sla_minutes, int) or freshness_sla_minutes < 15 or freshness_sla_minutes > 1440:
            findings.append(
                _finding(
                    "error",
                    stack,
                    f"{path}.freshnessSlaMinutes",
                    "source runtime observability freshnessSlaMinutes must be between 15 and 1440",
                )
            )

        if entry.get("observabilityStates") != OBSERVABILITY_STATUS_MODEL:
            findings.append(
                _finding(
                    "error",
                    stack,
                    f"{path}.observabilityStates",
                    "source runtime observability must use the shared contract probe status model",
                )
            )

        runtime = runtimes_by_id.get(runtime_id)
        if enabled and runtime is None:
            findings.append(
                _finding(
                    "error",
                    stack,
                    f"{path}.sourceRuntimeId",
                    "source runtime observability must reference a configured source runtime when enabled",
                )
            )
        if enabled and runtime is not None:
            actual_source = str(runtime.get("sourceId", "")).strip()
            if actual_source != source_system:
                findings.append(
                    _finding(
                        "error",
                        stack,
                        f"{path}.sourceSystem",
                        f"source runtime observability sourceSystem must match source runtime sourceId {actual_source!r}",
                    )
                )
            runtime_config = runtime.get("config") or {}
            actual_family = str(runtime_config.get("family", "")).strip() if isinstance(runtime_config, dict) else ""
            if actual_family and actual_family != runtime_class:
                findings.append(
                    _finding(
                        "error",
                        stack,
                        f"{path}.runtimeClass",
                        f"source runtime observability runtimeClass must match runtime family {actual_family!r}",
                    )
                )

    for key, expected_enabled in sorted(expected_entries.items()):
        if key not in seen:
            source_system, runtime_id, runtime_class = key
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:sourceRuntimeObservability",
                    f"source runtime observability entry for {source_system}/{runtime_class} ({runtime_id}) is missing",
                )
            )
            continue
        matching = [
            entry
            for entry in observability_entries
            if isinstance(entry, dict)
            and (
                str(entry.get("sourceSystem", "")).strip(),
                str(entry.get("sourceRuntimeId", "")).strip(),
                str(entry.get("runtimeClass", "")).strip(),
            )
            == key
        ]
        if matching and matching[0].get("enabled") is not expected_enabled:
            source_system, _, runtime_class = key
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:sourceRuntimeObservability",
                    f"source runtime observability entry for {source_system}/{runtime_class} must set enabled={expected_enabled}",
                )
            )


def _validate_neo4j_secret_import_coverage(stack: str, config: dict[str, Any], findings: list[Finding]) -> None:
    import_arns = config.get("neo4jSecretImportArns") or {}
    if not import_arns:
        return
    if not isinstance(import_arns, dict):
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:neo4jSecretImportArns",
                "must be a mapping from generated runtime secret key to imported secret ARN",
            )
        )
        return

    missing = sorted(NEO4J_GENERATED_RUNTIME_SECRET_KEYS - set(import_arns))
    for key in missing:
        findings.append(
            _finding(
                "error",
                stack,
                f"cerebro:neo4jSecretImportArns.{key}",
                "generated runtime secret imports must include every Pulumi-managed runtime credential secret",
            )
        )


def _validate_mcp_oauth_contract(stack: str, config: dict[str, Any], findings: list[Finding]) -> None:
    if config.get("mcpOauthEnabled") is not True:
        return

    if config.get("apiAuthEnabled") is not True:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:apiAuthEnabled",
                "MCP OAuth requires API auth to remain enabled",
            )
        )
    issuer = str(config.get("mcpOauthUpstreamIssuer") or "").strip()
    if not issuer.startswith("https://"):
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:mcpOauthUpstreamIssuer",
                "MCP OAuth upstream issuer must be an HTTPS URL",
            )
        )
    redirect_uri = str(config.get("mcpOauthUpstreamRedirectUri") or "").strip()
    if not redirect_uri.startswith("https://") or not redirect_uri.endswith("/oauth/callback"):
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:mcpOauthUpstreamRedirectUri",
                "MCP OAuth redirect URI must be HTTPS and end with /oauth/callback",
            )
        )
    for key in ("mcpOauthUpstreamClientIdSecretName", "mcpOauthUpstreamClientSecretName", "mcpOauthTenantId"):
        if not str(config.get(key) or "").strip():
            findings.append(_finding("error", stack, f"cerebro:{key}", "MCP OAuth configuration must be non-empty"))
    security_groups = config.get("mcpOauthSecurityGroups") or []
    if not isinstance(security_groups, list) or not security_groups or any(not str(group).strip() for group in security_groups):
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:mcpOauthSecurityGroups",
                "MCP OAuth must declare at least one upstream security group",
            )
        )
    allowed_tenants = {str(tenant).strip() for tenant in config.get("allowedTenants") or [] if str(tenant).strip()}
    mcp_tenant = str(config.get("mcpOauthTenantId") or "").strip()
    if mcp_tenant and mcp_tenant not in allowed_tenants:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:mcpOauthTenantId",
                "MCP OAuth tenant must be included in allowedTenants",
            )
        )
    mcp_allowed_tenants = {str(tenant).strip() for tenant in config.get("mcpOauthAllowedTenants") or [] if str(tenant).strip()}
    if not mcp_allowed_tenants:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:mcpOauthAllowedTenants",
                "MCP OAuth must declare an explicit tenant allowlist",
            )
        )
    elif not mcp_allowed_tenants.issubset(allowed_tenants):
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:mcpOauthAllowedTenants",
                "MCP OAuth allowed tenants must be a subset of allowedTenants",
            )
        )


def _otel_endpoint_parts(raw: str) -> tuple[str, str]:
    parsed = urlparse(raw.strip())
    return parsed.scheme.lower(), (parsed.hostname or "").lower()


def _otel_endpoint_is_loopback(raw: str) -> bool:
    _, host = _otel_endpoint_parts(raw)
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_otel_config(stack: str, config: dict[str, Any], findings: list[Finding]) -> None:
    protocol = str(config.get("otelExporterOtlpProtocol") or "").strip()
    if protocol and protocol not in OTEL_EXPORTER_PROTOCOLS:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:otelExporterOtlpProtocol",
                "OTLP protocol must be http/protobuf or grpc",
            )
        )

    collector_enabled = config.get("otelCollectorEnabled") is True
    endpoints = [
        ("cerebro:otelExporterOtlpEndpoint", str(config.get("otelExporterOtlpEndpoint") or "").strip()),
        ("cerebro:otelExporterOtlpTracesEndpoint", str(config.get("otelExporterOtlpTracesEndpoint") or "").strip()),
        ("cerebro:otelExporterOtlpMetricsEndpoint", str(config.get("otelExporterOtlpMetricsEndpoint") or "").strip()),
    ]
    configured_endpoints = [endpoint for _, endpoint in endpoints if endpoint]
    if config.get("otelEnabled") is True and not configured_endpoints and not collector_enabled:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:otelEnabled",
                "otelEnabled requires an OTLP endpoint, traces endpoint, or metrics endpoint",
            )
        )

    insecure = config.get("otelExporterOtlpInsecure") is True
    for path, endpoint in endpoints:
        if not endpoint:
            continue
        scheme, host = _otel_endpoint_parts(endpoint)
        if not scheme or not host:
            findings.append(
                _finding(
                    "error",
                    stack,
                    path,
                    "OTLP endpoint must be an absolute http(s) URL",
                )
            )
            continue
        if scheme not in {"http", "https"}:
            findings.append(
                _finding(
                    "error",
                    stack,
                    path,
                    "OTLP endpoint scheme must be http or https",
                )
            )
            continue
        loopback = _otel_endpoint_is_loopback(endpoint)
        if scheme == "http" and (not insecure or not loopback):
            findings.append(
                _finding(
                    "error",
                    stack,
                    path,
                    "plain HTTP OTLP endpoints are only allowed for loopback collectors with otelExporterOtlpInsecure=true",
                )
            )
        if collector_enabled and not loopback:
            findings.append(
                _finding(
                    "error",
                    stack,
                    path,
                    "otelCollectorEnabled requires app OTLP endpoints to stay on loopback; put backend export in otelCollectorConfigSecretName",
                )
            )
        if insecure and not (scheme == "http" and loopback):
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:otelExporterOtlpInsecure",
                    "otelExporterOtlpInsecure is only allowed with loopback HTTP OTLP endpoints",
                )
            )

    sample_rate = config.get("otelTracesSampleRate")
    parsed_sample_rate: float | None = None
    if isinstance(sample_rate, bool):
        parsed_sample_rate = None
    elif isinstance(sample_rate, int | float):
        parsed_sample_rate = float(sample_rate)
    elif isinstance(sample_rate, str) and sample_rate.strip():
        try:
            parsed_sample_rate = float(sample_rate.strip())
        except ValueError:
            parsed_sample_rate = None

    if sample_rate is not None and (
        parsed_sample_rate is None
        or not math.isfinite(parsed_sample_rate)
        or parsed_sample_rate < 0
        or parsed_sample_rate > 1
    ):
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:otelTracesSampleRate",
                "OTEL trace sample rate must be a number from 0 to 1",
            )
        )

    headers_secret_name = str(config.get("otelExporterOtlpHeadersSecretName") or "").strip()
    if headers_secret_name and ("=" in headers_secret_name or "," in headers_secret_name):
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:otelExporterOtlpHeadersSecretName",
                "OTLP headers must be provided by secret name, not inline header material",
            )
        )
    if str(config.get("otelExporterOtlpHeaders") or "").strip():
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:otelExporterOtlpHeaders",
                "plain OTLP header config is forbidden; use cerebro:otelExporterOtlpHeadersSecretName",
            )
        )

    collector_image = str(config.get("otelCollectorImage") or "").strip()
    collector_config_secret_name = str(config.get("otelCollectorConfigSecretName") or "").strip()
    if collector_enabled:
        if not collector_image:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:otelCollectorImage",
                    "otelCollectorImage is required when otelCollectorEnabled is true",
                )
            )
        if not collector_config_secret_name:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:otelCollectorConfigSecretName",
                    "otelCollectorConfigSecretName is required when otelCollectorEnabled is true",
                )
            )
        if headers_secret_name:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:otelExporterOtlpHeadersSecretName",
                    "otelExporterOtlpHeadersSecretName is ignored when otelCollectorEnabled is true; put exporter auth in otelCollectorConfigSecretName",
                )
            )
    if collector_config_secret_name and ("=" in collector_config_secret_name or "," in collector_config_secret_name):
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:otelCollectorConfigSecretName",
                "OTEL collector config must be provided by secret name, not inline config material",
            )
        )


def validate_stack(path: Path) -> list[Finding]:
    stack = _stack_name(path)
    config = _load_config(path)
    findings: list[Finding] = []
    try:
        config = apply_source_runtime_rollouts(config)
    except SourceRuntimeRolloutError as exc:
        findings.append(_finding("error", stack, "cerebro:sourceRuntimeRollouts", str(exc)))

    image_tag = str(config.get("imageTag", "")).strip()
    if not image_tag:
        findings.append(_finding("error", stack, "cerebro:imageTag", "image tag is required"))
    elif _parse_image_tag(image_tag) is None:
        findings.append(_finding("error", stack, "cerebro:imageTag", f"image tag {image_tag!r} must look like vX.Y.Z"))

    _validate_otel_config(stack, config, findings)

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
    # Active environments normally require >=2 API tasks for latency
    # headroom, but the secheck device-auth surface protects against DPoP
    # proof replay using an in-process per-replica jti cache (see
    # internal/deviceauth/dpop.go). When device-auth is enabled, raising
    # apiMaxInstances above 1 would make a legitimate proof routed to a
    # different replica than the one that initially saw it look like a
    # replay -> 401. The Cerebro server fails closed at startup
    # (errDeviceAuthRequiresSharedDPoPReplay); we mirror that invariant
    # HERE so the latency-headroom rule does not lie about what is
    # actually safe to deploy. Once shared replay state ships
    # (Phase-2: Redis-backed jti cache) this exemption can be removed.
    device_auth_enabled = config.get("deviceAuthEnabled") is True
    in_active_env = (
        stack == "sec-dev"
        or "prod" in str(config.get("environment", stack)).lower()
        or stack.endswith("prod")
    )
    nats_cpu = config.get("natsCpu", 512)
    nats_memory = config.get("natsMemory", 1024)
    jetstream_publish_max_in_flight = config.get("jetstreamPublishMaxInFlight", 0)
    jetstream_publish_retry_max_elapsed = config.get("jetstreamPublishRetryMaxElapsed")
    nats_efs_throughput_mode = str(config.get("natsEfsThroughputMode", "bursting")).strip().lower()
    nats_efs_provisioned_throughput = config.get("natsEfsProvisionedThroughputMibps")
    jetstream_discard_policy = str(config.get("jetstreamDiscardPolicy", "old")).strip().lower()
    if jetstream_discard_policy not in {"old", "new"}:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:jetstreamDiscardPolicy",
                "JetStream discard policy must be old or new",
            )
        )
    valid_nats_efs_throughput_modes = {"bursting", "elastic", "provisioned"}
    if nats_efs_throughput_mode not in valid_nats_efs_throughput_modes:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:natsEfsThroughputMode",
                "NATS EFS throughput mode must be one of: bursting, elastic, provisioned",
            )
        )
    if nats_efs_throughput_mode == "provisioned":
        if not isinstance(nats_efs_provisioned_throughput, int) or nats_efs_provisioned_throughput <= 0:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:natsEfsProvisionedThroughputMibps",
                    "provisioned NATS EFS throughput requires a positive MiB/s value",
                )
            )
    elif nats_efs_provisioned_throughput not in (None, 0):
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:natsEfsProvisionedThroughputMibps",
                "NATS EFS provisioned throughput is only valid when cerebro:natsEfsThroughputMode is provisioned",
            )
        )
    if in_active_env:
        if not isinstance(nats_cpu, int) or nats_cpu < 2048:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:natsCpu",
                    "active Cerebro environments must allocate at least 2048 CPU units to NATS JetStream for wide-event headroom",
                )
            )
        if not isinstance(nats_memory, int) or nats_memory < ACTIVE_NATS_MIN_MEMORY_MIB:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:natsMemory",
                    f"active Cerebro environments must allocate at least {ACTIVE_NATS_MIN_MEMORY_MIB} MiB to NATS JetStream for wide-event restore headroom",
                )
            )
        if not isinstance(jetstream_publish_max_in_flight, int) or jetstream_publish_max_in_flight < ACTIVE_JETSTREAM_MIN_PUBLISH_MAX_IN_FLIGHT:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:jetstreamPublishMaxInFlight",
                    f"active Cerebro environments must set JetStream publish max-in-flight to at least {ACTIVE_JETSTREAM_MIN_PUBLISH_MAX_IN_FLIGHT}",
                )
            )
        retry_max_elapsed_seconds = _parse_duration_seconds(jetstream_publish_retry_max_elapsed)
        if retry_max_elapsed_seconds is None or retry_max_elapsed_seconds < ACTIVE_JETSTREAM_MIN_PUBLISH_RETRY_MAX_ELAPSED_SECONDS:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:jetstreamPublishRetryMaxElapsed",
                    "active Cerebro environments must keep JetStream publish retry max elapsed at least 5m for NATS restore headroom",
                )
            )
        if nats_efs_throughput_mode not in {"elastic", "provisioned"}:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:natsEfsThroughputMode",
                    "active Cerebro environments must use elastic or provisioned EFS throughput for NATS JetStream restore headroom",
                )
            )
    if in_active_env and not device_auth_enabled and (
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
    if device_auth_enabled and isinstance(api_max_instances, int) and api_max_instances > 1:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:apiMaxInstances",
                "cerebro:deviceAuthEnabled requires apiMaxInstances=1 (in-process DPoP replay cache); "
                "lift this only after shared replay state is configured",
            )
        )
    graph_agent_llm_provider = str(config.get("graphAgentLlmProvider", "")).strip().lower()
    graph_agent_llm_model = str(config.get("graphAgentLlmModel", "")).strip()
    if graph_agent_llm_provider and graph_agent_llm_provider not in {"openrouter", "bedrock"}:
        findings.append(_finding("error", stack, "cerebro:graphAgentLlmProvider", "graph agent LLM provider must be openrouter or bedrock"))
    if graph_agent_llm_provider == "openrouter":
        if not str(config.get("openrouterApiKeySecret", "")).strip():
            findings.append(_finding("error", stack, "cerebro:openrouterApiKeySecret", "OpenRouter provider must declare the API key secret import"))
        if not graph_agent_llm_model:
            findings.append(_finding("error", stack, "cerebro:graphAgentLlmModel", "OpenRouter provider must set an explicit OpenRouter model id"))
        elif "/" not in graph_agent_llm_model:
            findings.append(_finding("error", stack, "cerebro:graphAgentLlmModel", "OpenRouter model must use provider/model form"))
        elif re.search(r"claude-[a-z0-9.-]+-\d{8}$", graph_agent_llm_model):
            findings.append(_finding("error", stack, "cerebro:graphAgentLlmModel", "OpenRouter model must use an OpenRouter slug, not an Anthropic dated model id"))
    if graph_agent_llm_provider == "bedrock":
        bedrock_region = str(config.get("bedrockRegion", "")).strip()
        if not graph_agent_llm_model:
            findings.append(_finding("error", stack, "cerebro:graphAgentLlmModel", "Bedrock provider must set an explicit Bedrock model or inference profile id"))
        elif "/" in graph_agent_llm_model and not graph_agent_llm_model.startswith("arn:aws:bedrock:"):
            findings.append(_finding("error", stack, "cerebro:graphAgentLlmModel", "Bedrock model must use a Bedrock model id, inference profile id, or ARN, not an OpenRouter slug"))
        elif not (BEDROCK_MODEL_ID_RE.match(graph_agent_llm_model) or BEDROCK_MODEL_ARN_RE.match(graph_agent_llm_model)):
            findings.append(_finding("error", stack, "cerebro:graphAgentLlmModel", "Bedrock model must be an Anthropic Bedrock model id, inference profile id, or ARN"))
        if not bedrock_region:
            findings.append(_finding("error", stack, "cerebro:bedrockRegion", "Bedrock provider must set the runtime AWS region"))
        elif not AWS_REGION_RE.match(bedrock_region):
            findings.append(_finding("error", stack, "cerebro:bedrockRegion", "Bedrock region must be a canonical AWS region"))
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
        "jetstreamStreamBytesAlarmThreshold",
        "awsServiceQuotaAlarmThresholdPercent",
        "monthlyCostBudgetLimitUsd",
    ):
        threshold = config.get(key, 0)
        if not isinstance(threshold, int) or threshold < 0:
            findings.append(_finding("error", stack, f"cerebro:{key}", "must be a non-negative integer"))

    buffer_state = config.get("orchestratorSqsBufferPipeState") or "STOPPED"
    if buffer_state not in {"RUNNING", "STOPPED"}:
        findings.append(_finding("error", stack, "cerebro:orchestratorSqsBufferPipeState", "must be RUNNING or STOPPED"))
    if config.get("orchestratorSqsBufferEnabled") is True and config.get("orchestratorStepFunctionsEnabled") is not True:
        findings.append(_finding("error", stack, "cerebro:orchestratorSqsBufferEnabled", "requires orchestratorStepFunctionsEnabled"))
    if config.get("orchestratorSqsBufferEnabled") is True and config.get("orchestratorEnabled") is not True:
        findings.append(_finding("error", stack, "cerebro:orchestratorSqsBufferEnabled", "requires orchestratorEnabled"))
    if config.get("syntheticsCanaryStart") is True and config.get("syntheticsCanaryEnabled") is not True:
        findings.append(_finding("error", stack, "cerebro:syntheticsCanaryStart", "requires syntheticsCanaryEnabled"))
    cloudtrail_log_group = str(config.get("cloudTrailAuditLogGroupName") or "").strip()
    if cloudtrail_log_group and any(char.isspace() for char in cloudtrail_log_group):
        findings.append(_finding("error", stack, "cerebro:cloudTrailAuditLogGroupName", "must not contain whitespace"))

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

    disabled_runtime_ids = _quarantined_source_runtime_ids(stack, config, findings)
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
        elif runtime_id in disabled_runtime_ids:
            findings.append(
                _finding(
                    "error",
                    stack,
                    f"{runtime_path}.id",
                    f"quarantined runtime {runtime_id!r} must not be declared in active sourceRuntimes",
                )
            )
        elif runtime_id in runtime_ids:
            findings.append(_finding("error", stack, f"{runtime_path}.id", f"duplicate runtime id {runtime_id!r}"))
        else:
            runtime_ids.add(runtime_id)

        lifecycle_state = str(runtime.get("lifecycleState") or SourceRuntimeLifecycleState.ACTIVE.value).strip()
        if lifecycle_state not in SOURCE_RUNTIME_LIFECYCLE_STATES:
            findings.append(
                _finding(
                    "error",
                    stack,
                    f"{runtime_path}.lifecycleState",
                    f"lifecycleState must be one of: {', '.join(sorted(SOURCE_RUNTIME_LIFECYCLE_STATES))}",
                )
            )
        elif lifecycle_state == SourceRuntimeLifecycleState.QUARANTINED.value:
            findings.append(
                _finding(
                    "error",
                    stack,
                    f"{runtime_path}.lifecycleState",
                    "quarantined runtimes must be removed from active sourceRuntimes and declared in temporarilyDisabledSourceRuntimes",
                )
            )

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
            if runtime_bucket != bucket or not source_runtime_scope.s3_prefix_covers(prefix, runtime_prefix):
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

        for secret_path in _plain_secret_paths(runtime_config, f"{runtime_path}.config"):
            findings.append(
                _finding(
                    "error",
                    stack,
                    secret_path,
                    "secret-like runtime config values must use env: references",
                )
            )

    _validate_source_runtime_service_bootstrap(stack, config, source_runtimes, runtime_ids, findings)

    schedules = config.get("orchestratorSchedules") or []
    if schedules and not isinstance(schedules, list):
        findings.append(_finding("error", stack, "cerebro:orchestratorSchedules", "must be a list"))
        schedules = []

    scheduled_runtime_ids: set[str] = set()
    top_level_command = config.get("orchestratorCommand")
    top_level_runtime_id = _runtime_id_from_command(top_level_command)
    if top_level_command:
        if top_level_runtime_id is None:
            if not schedules:
                scheduled_runtime_ids.update(runtime_ids)
        elif top_level_runtime_id in disabled_runtime_ids:
            findings.append(
                _finding(
                    "error",
                    stack,
                    "cerebro:orchestratorCommand",
                    f"quarantined runtime {top_level_runtime_id!r} must not be referenced by cerebro:orchestratorCommand",
                )
            )
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
            if not schedules:
                scheduled_runtime_ids.add(top_level_runtime_id)
        if not schedules:
            guarded_runtime_ids = [top_level_runtime_id] if top_level_runtime_id is not None else sorted(runtime_ids)
            for guarded_runtime_id in guarded_runtime_ids:
                _validate_graph_page_budget(stack, guarded_runtime_id, top_level_command, "cerebro:orchestratorCommand", findings)

    schedule_names: set[str] = set()
    environment_name = str(config.get("environment", stack)).strip() or stack
    schedule_limit = _orchestrator_schedule_limit(stack)
    eventbridge_schedule_count = sum(1 for schedule in schedules if isinstance(schedule, dict) and _schedule_backend(schedule) == "eventbridge")
    if schedule_limit is not None and eventbridge_schedule_count > schedule_limit:
        findings.append(
            _finding(
                "error",
                stack,
                "cerebro:orchestratorSchedules",
                f"EventBridge-backed orchestrator schedule count {eventbridge_schedule_count} exceeds EventBridge rule capacity {schedule_limit}",
            )
        )
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
            backend = _schedule_backend(schedule)
            if backend not in {"eventbridge", "scheduler"}:
                findings.append(_finding("error", stack, f"{schedule_path}.backend", "schedule backend must be eventbridge or scheduler"))
            state = _schedule_state(schedule)
            if state not in {"ENABLED", "DISABLED"}:
                findings.append(_finding("error", stack, f"{schedule_path}.state", "schedule state must be ENABLED or DISABLED"))
            schedule_resource_name = _orchestrator_rule_name(environment_name, name)
            if len(schedule_resource_name) > EVENTBRIDGE_RULE_NAME_MAX_LENGTH:
                findings.append(
                    _finding(
                        "error",
                        stack,
                        f"{schedule_path}.name",
                        f"orchestrator schedule resource name {schedule_resource_name!r} must be at most {EVENTBRIDGE_RULE_NAME_MAX_LENGTH} characters",
                    )
                )

        if not str(schedule.get("scheduleExpression", "")).strip():
            findings.append(_finding("error", stack, f"{schedule_path}.scheduleExpression", "schedule expression is required"))

        task_count = schedule.get("taskCount", 1)
        if not isinstance(task_count, int) or task_count < 1:
            findings.append(_finding("error", stack, f"{schedule_path}.taskCount", "taskCount must be a positive integer"))

        runtime_id = _runtime_id_from_command(schedule.get("command"))
        if runtime_id is None:
            findings.append(_finding("error", stack, f"{schedule_path}.command", "command must include runtime_id=<id>"))
        elif runtime_id in disabled_runtime_ids:
            findings.append(
                _finding(
                    "error",
                    stack,
                    f"{schedule_path}.command",
                    f"quarantined runtime {runtime_id!r} must not be referenced by cerebro:orchestratorSchedules",
                )
            )
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

    _validate_cosmo_gitops(stack, config, source_runtimes, schedules, source_secret_names, disabled_runtime_ids, findings)
    _validate_sec_dev_aws_coverage(stack, config, source_runtimes, schedules, findings)
    _validate_go_prod_aws_coverage(stack, source_runtimes, schedules, findings)
    _validate_panopticon_wiring(stack, config, source_runtimes, schedules, findings)
    _validate_source_runtime_observability(stack, config, source_runtimes, findings)
    _validate_neo4j_secret_import_coverage(stack, config, findings)
    _validate_mcp_oauth_contract(stack, config, findings)

    environment = str(config.get("environment", stack)).lower()
    is_prod = stack.endswith("prod") or "prod" in environment
    is_sec_dev = stack == "sec-dev" or environment == "sec-dev"
    if config.get("retainLegacyJobsTableForDeletionProtectionTransition") is True:
        findings.append(
            _finding(
                "warning",
                stack,
                "cerebro:retainLegacyJobsTableForDeletionProtectionTransition",
                "legacy jobs table transition flag is still enabled; remove it after confirming the table can be deleted",
            )
        )
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


def _source_runtime_observability_summaries(path: Path) -> list[str]:
    stack = _stack_name(path)
    config = _load_config(path)
    entries = config.get("sourceRuntimeObservability") or []
    if not isinstance(entries, list):
        return []
    summaries = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        source_system = str(entry.get("sourceSystem", "")).strip()
        runtime_id = str(entry.get("sourceRuntimeId", "")).strip()
        runtime_class = str(entry.get("runtimeClass", "")).strip()
        enabled = entry.get("enabled")
        freshness = entry.get("freshnessSlaMinutes")
        dashboard = entry.get("dashboardEnabled")
        alarm = entry.get("alarmEnabled")
        if source_system and runtime_id and runtime_class:
            summaries.append(
                f"OK: {stack} sourceRuntimeObservability {source_system}/{runtime_class} "
                f"runtime={runtime_id} enabled={enabled} freshnessSlaMinutes={freshness} "
                f"dashboard={dashboard} alarm={alarm}"
            )
    return summaries


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
    if not has_error:
        for path in paths:
            for summary in _source_runtime_observability_summaries(path):
                print(summary)
    return 1 if has_error or (args.strict_warnings and has_warning) else 0


if __name__ == "__main__":
    sys.exit(main())
