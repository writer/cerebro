"""Producer for detecting publicly accessible SQS queues."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import resolve_rule_id

from .base import BaseAWSProducer


def _is_public_policy(policy: dict[str, Any] | None, account_id: str | None) -> bool:
    """Check if SQS policy allows public access."""
    if not policy:
        return False

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal", {})
        if principal == "*" or (isinstance(principal, dict) and "*" in str(principal.get("AWS", ""))):
            condition = statement.get("Condition", {})
            if not _has_account_restriction(condition, account_id):
                return True

    return False


def _has_account_restriction(condition: dict[str, Any], account_id: str | None) -> bool:
    """Check if condition restricts to same account."""
    if not condition or not account_id:
        return False

    for _, conditions in condition.items():
        if not isinstance(conditions, dict):
            continue
        for key, value in conditions.items():
            if "sourceaccount" in key.lower() or "sourceowner" in key.lower():
                if value == account_id:
                    return True
    return False


@register_producer
class SQSPublicAccessProducer(BaseAWSProducer):
    """Detect SQS queues with public access policies."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.sqs.queue"}

    @property
    def finding_name(self) -> str:
        return "AWS: SQS Queue Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "aws_sqs_public_access"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "SQS queue has a policy that allows public access."

    @property
    def remediation(self) -> str:
        return (
            "Update the queue policy to restrict access to specific principals. "
            "Remove wildcard (*) principals. "
            "Add conditions to limit access to specific accounts."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-3", "AC-6"],
            "cwe": ["CWE-284"],
            "cis_aws": ["2.1.1"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate SQS queue for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        policy = data.get("policy")
        if isinstance(policy, str):
            import json
            try:
                policy = json.loads(policy)
            except (json.JSONDecodeError, TypeError):
                return findings

        account_id = data.get("account_id")
        if not _is_public_policy(policy, account_id):
            return findings

        encrypted = data.get("kms_master_key_id") or data.get("sqs_managed_sse_enabled")

        risk_factors: list[str] = ["public_policy"]
        if not encrypted:
            risk_factors.append("not_encrypted")

        evidence = {
            "queue_name": resource.name,
            "queue_arn": resource.external_id,
            "queue_url": data.get("queue_url"),
            "encrypted": bool(encrypted),
            "policy": policy,
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"SQS queue {resource.name} is publicly accessible",
                summary=f"Queue has public policy. Encrypted: {bool(encrypted)}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
