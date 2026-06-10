#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from cerebro_task_roles import resolve_task_role_arns


EXPECTED_STACK_ACCOUNTS = {
    "sec-dev": "944130631940",
    "go-prod": "837279440628",
}

ROLE_ARN_RE = re.compile(r"^arn:(?P<partition>aws|aws-us-gov|aws-cn):iam::(?P<account>[0-9]{12}):role/(?P<name>[A-Za-z0-9+=,.@_/-]+)$")


@dataclass(frozen=True)
class TrustFinding:
    account_id: str
    role_name: str
    principal_arn: str


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
    return {key.removeprefix("cerebro:"): value for key, value in config.items() if isinstance(key, str) and key.startswith("cerebro:")}


def _aws(args: list[str], region: str, profile: str | None = None) -> dict[str, Any]:
    command = ["aws", *args, "--region", region, "--output", "json"]
    env = os.environ.copy()
    if profile:
        env["AWS_PROFILE"] = profile
    output = subprocess.check_output(command, env=env, text=True)
    return json.loads(output) if output.strip() else {}


def _source_runtime_role_arns(config: dict[str, Any], *, excluded_source_ids: set[str] | None = None) -> list[str]:
    excluded_source_ids = excluded_source_ids or set()
    role_arns: set[str] = set()
    for runtime in config.get("sourceRuntimes") or []:
        if not isinstance(runtime, dict):
            continue
        source_id = str(runtime.get("sourceId") or "").strip()
        if source_id in excluded_source_ids:
            continue
        runtime_config = runtime.get("config") or {}
        if not isinstance(runtime_config, dict):
            continue
        role_arn = str(runtime_config.get("role_arn", "")).strip()
        if role_arn:
            role_arns.add(role_arn)
    return sorted(role_arns)


def _same_account_role_arns(role_arns: list[str], account_id: str) -> list[str]:
    result: list[str] = []
    for role_arn in role_arns:
        match = ROLE_ARN_RE.fullmatch(role_arn)
        if not match:
            raise ValueError(f"invalid AWS role ARN: {role_arn}")
        if match.group("account") == account_id:
            result.append(role_arn)
    return result


def _expected_stack_principals(stack: str, config: dict[str, Any], account_id: str) -> list[str]:
    return resolve_task_role_arns(stack, config, account_id).as_principals()


def _expected_stack_principals_from_outputs(
    stack: str,
    config: dict[str, Any],
    account_id: str,
    outputs: dict[str, Any] | None = None,
) -> list[str]:
    return resolve_task_role_arns(stack, config, account_id, outputs).as_principals()


def _action_allows_assume_role(action: Any) -> bool:
    actions = [action] if isinstance(action, str) else action if isinstance(action, list) else []
    return any(str(item).lower() == "sts:assumerole" for item in actions)


def _trusted_principals(policy_document: dict[str, Any]) -> set[str]:
    trusted: set[str] = set()
    statements = policy_document.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow" or not _action_allows_assume_role(statement.get("Action")):
            continue
        principal = statement.get("Principal") or {}
        if not isinstance(principal, dict):
            continue
        aws_principal = principal.get("AWS") or []
        values = [aws_principal] if isinstance(aws_principal, str) else aws_principal if isinstance(aws_principal, list) else []
        trusted.update(str(value) for value in values)
    return trusted


def _find_missing_trust(role_arns: list[str], expected_principals: list[str], role_policies: dict[str, dict[str, Any]]) -> list[TrustFinding]:
    findings: list[TrustFinding] = []
    for role_arn in role_arns:
        match = ROLE_ARN_RE.fullmatch(role_arn)
        if not match:
            raise ValueError(f"invalid AWS role ARN: {role_arn}")
        trusted = _trusted_principals(role_policies[role_arn])
        for principal in expected_principals:
            if principal not in trusted:
                findings.append(TrustFinding(match.group("account"), match.group("name"), principal))
    return findings


def _markdown_escape(value: str) -> str:
    return value.replace("|", "\\|")


def _finding_role_arn(finding: TrustFinding) -> str:
    return f"arn:aws:iam::{finding.account_id}:role/{finding.role_name}"


def _summary_markdown(stack: str, role_arns: list[str], expected_principals: list[str], findings: list[TrustFinding]) -> str:
    status = "failed" if findings else "passed"
    lines = [
        f"## AWS Scan Role Trust: `{stack}`",
        "",
        f"Status: **{status}**",
        f"Checked roles: `{len(role_arns)}`",
        f"Expected principals per role: `{len(expected_principals)}`",
        "",
    ]
    if findings:
        lines.extend(
            [
                "| Target role | Missing trusted principal |",
                "| --- | --- |",
            ]
        )
        for finding in findings:
            lines.append(f"| `{_markdown_escape(_finding_role_arn(finding))}` | `{_markdown_escape(finding.principal_arn)}` |")
    else:
        lines.append("All checked source runtime roles trust the expected task principals.")
    lines.append("")
    return "\n".join(lines)


def _write_github_summary(stack: str, role_arns: list[str], expected_principals: list[str], findings: list[TrustFinding]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write(_summary_markdown(stack, role_arns, expected_principals, findings))


def _parse_profile_map(entries: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for entry in entries:
        if "=" not in entry:
            raise ValueError(f"profile mapping {entry!r} must use ACCOUNT_ID=PROFILE")
        account_id, profile = entry.split("=", 1)
        account_id = account_id.strip()
        profile = profile.strip()
        if not re.fullmatch(r"[0-9]{12}", account_id) or not profile:
            raise ValueError(f"profile mapping {entry!r} must use ACCOUNT_ID=PROFILE")
        result[account_id] = profile
    return result


def _load_outputs(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    with path.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a JSON object from `pulumi stack output --json`")
    return loaded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify AWS source scan roles trust the ECS task roles declared by a Cerebro stack.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument(
        "--pulumi-outputs-json",
        type=Path,
        help="Optional JSON from `pulumi stack output --json`; task-role outputs are consumed when present and validated against deterministic fallback names.",
    )
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--profile-by-account", action="append", default=[], help="AWS profile to read a target role account, as ACCOUNT_ID=PROFILE.")
    parser.add_argument("--same-account-only", action="store_true", help="Verify only source roles in the stack account.")
    parser.add_argument(
        "--exclude-source-id",
        action="append",
        default=[],
        help="Exclude source runtime roles for a source id that is intentionally readiness-only for this check.",
    )
    args = parser.parse_args(argv)

    stack = _stack_name(args.stack_file)
    config = _load_config(args.stack_file)
    stack_account = EXPECTED_STACK_ACCOUNTS.get(stack)
    if not stack_account:
        raise RuntimeError(f"no expected AWS account is registered for stack {stack!r}")

    excluded_source_ids = {source_id.strip() for source_id in args.exclude_source_id if source_id.strip()}
    role_arns = _source_runtime_role_arns(config, excluded_source_ids=excluded_source_ids)
    if args.same_account_only:
        role_arns = _same_account_role_arns(role_arns, stack_account)
    expected_principals = _expected_stack_principals_from_outputs(stack, config, stack_account, _load_outputs(args.pulumi_outputs_json))
    profiles = _parse_profile_map(args.profile_by_account)

    role_policies: dict[str, dict[str, Any]] = {}
    for role_arn in role_arns:
        match = ROLE_ARN_RE.fullmatch(role_arn)
        if not match:
            raise RuntimeError(f"invalid AWS role ARN: {role_arn}")
        account_id = match.group("account")
        profile = profiles.get(account_id)
        if not profile and account_id != stack_account:
            raise RuntimeError(f"missing --profile-by-account {account_id}=PROFILE for {role_arn}")
        role = _aws(["iam", "get-role", "--role-name", match.group("name")], args.region, profile).get("Role") or {}
        role_policies[role_arn] = role.get("AssumeRolePolicyDocument") or {}

    findings = _find_missing_trust(role_arns, expected_principals, role_policies)
    _write_github_summary(stack, role_arns, expected_principals, findings)
    for finding in findings:
        print(
            f"ERROR: arn:aws:iam::{finding.account_id}:role/{finding.role_name} does not trust {finding.principal_arn}",
            file=sys.stderr,
        )
    if not findings:
        print(f"verified {len(role_arns)} AWS scan role trust policies for {stack}")
    return 1 if findings else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
