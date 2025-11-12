"""Detect IAM roles with overly permissive trust policies."""

from __future__ import annotations

import re
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.registry import register_producer

from .base import BaseAWSProducer

ACCOUNT_ARN_RE = re.compile(r"^arn:aws:iam::(\d{12}):")
RESTRICTIVE_CONDITION_KEYS = {
    "aws:sourcearn",
    "aws:sourceaccount",
    "aws:principalarn",
    "aws:principalaccount",
    "aws:principalorgid",
    "aws:principalservice",
    "aws:principalorgpath",
    "aws:principaltype",
}
ASSUME_ACTIONS = {
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
}


def _ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _contains_assume_action(actions: Any) -> bool:
    for action in _ensure_list(actions):
        if isinstance(action, str) and action.lower() in ASSUME_ACTIONS:
            return True
    return False


def _is_public_principal(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for key, value in principal.items():
            if isinstance(value, str) and value == "*":
                return True
            if isinstance(value, list) and any(item == "*" for item in value):
                return True
            if key.lower() == "aws":
                if any(item == "*" for item in _ensure_list(value)):
                    return True
    if isinstance(principal, list):
        return any(_is_public_principal(item) for item in principal)
    return False


def _normalize_account(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    if trimmed == "*":
        return None
    if trimmed.isdigit() and len(trimmed) == 12:
        return trimmed
    match = ACCOUNT_ARN_RE.match(trimmed)
    if match:
        return match.group(1)
    return None


def _extract_external_accounts(principal: Any, local_account: str | None) -> list[str]:
    accounts: set[str] = set()
    if isinstance(principal, dict):
        aws_value = principal.get("AWS")
        if aws_value is not None:
            for entry in _ensure_list(aws_value):
                account = _normalize_account(entry)
                if account and account != local_account:
                    accounts.add(account)
    elif isinstance(principal, list):
        for item in principal:
            accounts.update(_extract_external_accounts(item, local_account))
    elif isinstance(principal, str):
        account = _normalize_account(principal)
        if account and account != local_account:
            accounts.add(account)
    return sorted(accounts)


def _condition_has_restriction(condition: Any) -> bool:
    if not condition:
        return False

    def _walk(node: Any) -> bool:
        if isinstance(node, dict):
            for key, value in node.items():
                key_lower = key.lower()
                if key_lower in RESTRICTIVE_CONDITION_KEYS:
                    return True
                if _walk(value):
                    return True
        elif isinstance(node, list):
            return any(_walk(item) for item in node)
        return False

    return _walk(condition)


def _iter_trust_statements(
    policy_document: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if not policy_document:
        return []
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [
        stmt
        for stmt in statements
        if stmt.get("Effect") == "Allow" and _contains_assume_action(stmt.get("Action"))
    ]


@register_producer
class AwsServiceAccountOpenAssumeProducer(BaseAWSProducer):
    """Detect IAM roles whose trust policies allow untrusted principals."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.iam.role"}

    @property
    def finding_name(self) -> str:
        return "AWS: IAM role trust policy is overly permissive"

    @property
    def rule_name(self) -> str:
        return "aws_service_role_open_trust"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "IAM role trust policy allows untrusted principals to assume the role"

    @property
    def remediation(self) -> str:
        return (
            "Restrict the role's trust policy to specific AWS accounts or principals "
            "and enforce conditions such as aws:SourceArn or aws:PrincipalOrgID."
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: dict[str, Any] | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        trust_policy = normalized.get("assume_role_policy") or {}
        account_id = normalized.get("account_id")

        exposures: list[dict[str, Any]] = []

        for statement in _iter_trust_statements(trust_policy):
            principal = statement.get("Principal")
            if not principal:
                continue

            if _condition_has_restriction(statement.get("Condition")):
                continue

            if _is_public_principal(principal):
                exposures.append(
                    {
                        "type": "public",
                        "statement_sid": statement.get("Sid"),
                    }
                )
                continue

            external_accounts = _extract_external_accounts(principal, account_id)
            if external_accounts:
                exposures.append(
                    {
                        "type": "external_account",
                        "accounts": external_accounts,
                        "statement_sid": statement.get("Sid"),
                    }
                )

        if not exposures:
            return []

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        severity = self.severity
        if any(exposure["type"] == "public" for exposure in exposures):
            severity = Severity.CRITICAL

        role_identifier = resource.name or resource.external_id

        summary_parts: list[str] = []
        for exposure in exposures:
            if exposure["type"] == "public":
                summary_parts.append(
                    "trust policy allows any principal to assume the role"
                )
            else:
                accounts = ", ".join(exposure["accounts"])
                summary_parts.append(
                    f"trust policy allows external accounts {accounts}"
                )

        evidence = {
            "role_arn": resource.external_id,
            "role_name": resource.name,
            "account_id": account_id,
            "exposures": exposures,
            "assume_role_policy": trust_policy,
            "attached_policies": normalized.get("attached_policies"),
            "inline_policies": list((normalized.get("inline_policies") or {}).keys()),
            "last_used": normalized.get("last_used"),
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(f"IAM role {role_identifier} trust policy is overly " "permissive"),
            summary="; ".join(summary_parts),
            evidence=evidence,
            severity=severity,
        )

        return [finding]
