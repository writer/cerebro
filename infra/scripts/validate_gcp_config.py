#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys
from typing import Any

import yaml


ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(?P<account>[0-9]{12}):role/(?P<name>[A-Za-z0-9+=,.@_/-]+)$")
ALLOWED_SCANNER_ROLES = {"roles/viewer", "roles/compute.viewer", "roles/logging.privateLogViewer"}
DEV_DISALLOWED_PROJECT_PATTERNS = ("prod", "production")


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
    return {
        key.removeprefix("cerebro:"): value
        for key, value in config.items()
        if isinstance(key, str) and key.startswith("cerebro:")
    }


def _finding(stack: str, path: str, message: str) -> Finding:
    return Finding("error", stack, path, message)


def validate_stack(path: Path) -> list[Finding]:
    stack = _stack_name(path)
    config = _load_config(path)
    findings: list[Finding] = []

    account_id = str(config.get("trustedAwsAccountId") or "").strip()
    if not re.fullmatch(r"[0-9]{12}", account_id):
        findings.append(_finding(stack, "cerebro:trustedAwsAccountId", "must be a 12 digit AWS account ID"))

    role_arns = config.get("trustedAwsRoleArns") or []
    if not isinstance(role_arns, list) or not role_arns:
        findings.append(_finding(stack, "cerebro:trustedAwsRoleArns", "must be a non-empty list"))
        role_arns = []
    seen_roles: set[str] = set()
    role_names_by_index: list[tuple[int, str]] = []
    for index, arn in enumerate(role_arns):
        arn = str(arn).strip()
        match = ROLE_ARN_RE.fullmatch(arn)
        if not match:
            findings.append(_finding(stack, f"cerebro:trustedAwsRoleArns[{index}]", "must be a valid AWS IAM role ARN"))
            continue
        if account_id and match.group("account") != account_id:
            findings.append(
                _finding(
                    stack,
                    f"cerebro:trustedAwsRoleArns[{index}]",
                    f"account {match.group('account')} must match trustedAwsAccountId {account_id}",
                )
            )
        role_name = match.group("name")
        if role_name in seen_roles:
            findings.append(_finding(stack, f"cerebro:trustedAwsRoleArns[{index}]", f"duplicate role name {role_name!r}"))
        seen_roles.add(role_name)
        role_names_by_index.append((index, role_name))

    for index, role_name in role_names_by_index:
        if not role_name.endswith("-task-role") or role_name.endswith("-worker-task-role"):
            continue
        worker_role_name = role_name.removesuffix("-task-role") + "-worker-task-role"
        if worker_role_name not in seen_roles:
            findings.append(
                _finding(
                    stack,
                    f"cerebro:trustedAwsRoleArns[{index}]",
                    f"task role {role_name!r} must be paired with worker role {worker_role_name!r}",
                )
            )

    projects = config.get("scannerRoleProjects") or []
    if not isinstance(projects, list) or not projects:
        findings.append(_finding(stack, "cerebro:scannerRoleProjects", "must be a non-empty list"))
        projects = []
    for index, project in enumerate(projects):
        project = str(project).strip()
        if not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project):
            findings.append(_finding(stack, f"cerebro:scannerRoleProjects[{index}]", "must be a valid GCP project ID"))
        normalized_project = project.replace("nonprod", "")
        if stack.endswith("dev") and any(pattern in normalized_project for pattern in DEV_DISALLOWED_PROJECT_PATTERNS):
            findings.append(
                _finding(
                    stack,
                    f"cerebro:scannerRoleProjects[{index}]",
                    f"dev WIF stack must not grant scanner roles on production-like project {project!r}",
                )
            )

    roles = config.get("scannerRoles") or []
    if not isinstance(roles, list) or not roles:
        findings.append(_finding(stack, "cerebro:scannerRoles", "must be a non-empty list"))
        roles = []
    for index, role in enumerate(roles):
        role = str(role).strip()
        if role not in ALLOWED_SCANNER_ROLES:
            findings.append(_finding(stack, f"cerebro:scannerRoles[{index}]", f"role {role!r} is not in the scanner role allowlist"))

    return findings


def _default_stack_paths(repo_root: Path) -> list[Path]:
    return sorted((repo_root / "infra" / "gcp").glob("Pulumi.*.yaml"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Cerebro GCP Pulumi stack config.")
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)

    findings: list[Finding] = []
    for path in args.paths or _default_stack_paths(args.repo_root):
        findings.extend(validate_stack(path))
    for finding in findings:
        print(f"{finding.severity.upper()}: {finding.stack} {finding.path}: {finding.message}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
