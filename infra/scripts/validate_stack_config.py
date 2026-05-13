#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


MIN_CROSS_TASK_SYNC_LOCK_VERSION = (2, 1, 25)
IMAGE_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$")
SECRET_KEY_RE = re.compile(r"(secret|token|password|api_?key|client_secret|private_key)", re.IGNORECASE)


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


def _runtime_id_from_command(command: Any) -> str | None:
    if not isinstance(command, list):
        return None
    for arg in command:
        text = str(arg).strip()
        if text.startswith("runtime_id="):
            runtime_id = text.split("=", 1)[1].strip()
            return runtime_id or None
    return None


def _is_plain_secret(key: str, value: Any) -> bool:
    if not SECRET_KEY_RE.search(key):
        return False
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    return bool(stripped) and not stripped.startswith("env:") and not stripped.startswith("${")


def _finding(severity: str, stack: str, path: str, message: str) -> Finding:
    return Finding(severity=severity, stack=stack, path=path, message=message)


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

    source_runtimes = config.get("sourceRuntimes") or []
    if source_runtimes and not isinstance(source_runtimes, list):
        findings.append(_finding("error", stack, "cerebro:sourceRuntimes", "must be a list"))
        source_runtimes = []

    runtime_ids: set[str] = set()
    source_secret_names = _source_secret_names(config.get("sourceSecretKeys") or [])
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

        if "backfill" in name.lower() and not any(key in schedule for key in ("expiresAt", "removeAfter", "expires_after")):
            findings.append(
                _finding(
                    "warning",
                    stack,
                    f"{schedule_path}.name",
                    "backfill schedules should include expiresAt/removeAfter metadata for retirement",
                )
            )

    environment = str(config.get("environment", stack)).lower()
    is_prod = stack.endswith("prod") or "prod" in environment
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

        allowed_tenants = config.get("allowedTenants") or []
        if not isinstance(allowed_tenants, list) or not allowed_tenants:
            findings.append(_finding("error", stack, "cerebro:allowedTenants", "production must declare allowed tenants"))

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

    for finding in findings:
        print(f"{finding.severity.upper()}: {finding.stack} {finding.path}: {finding.message}")

    has_error = any(finding.severity == "error" for finding in findings)
    has_warning = any(finding.severity == "warning" for finding in findings)
    return 1 if has_error or (args.strict_warnings and has_warning) else 0


if __name__ == "__main__":
    sys.exit(main())
