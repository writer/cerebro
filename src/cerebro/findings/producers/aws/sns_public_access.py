"""Producer for detecting publicly accessible SNS topics."""

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


@register_producer
class SNSPublicAccessProducer(BaseAWSProducer):
    """Detect SNS topics with public access policies."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.sns.topic"}

    @property
    def finding_name(self) -> str:
        return "AWS: SNS Topic Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "aws_sns_public_access"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "SNS topic has a policy that allows public access."

    @property
    def remediation(self) -> str:
        return (
            "Update the topic policy to restrict access to specific principals. "
            "Remove wildcard (*) principals. "
            "Enable KMS encryption for the topic."
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
        """Evaluate SNS topic for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        policy = data.get("policy")
        if isinstance(policy, str):
            import json
            try:
                policy = json.loads(policy)
            except (json.JSONDecodeError, TypeError):
                return findings

        if not policy:
            return findings

        # Check for public access
        is_public = False
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal", {})
            if principal == "*" or (isinstance(principal, dict) and "*" in str(principal.get("AWS", ""))):
                if "Condition" not in statement:
                    is_public = True
                    break

        if not is_public:
            return findings

        kms_key = data.get("kms_master_key_id")
        risk_factors: list[str] = ["public_policy"]
        if not kms_key:
            risk_factors.append("not_encrypted")

        evidence = {
            "topic_name": resource.name,
            "topic_arn": resource.external_id,
            "kms_master_key_id": kms_key,
            "policy": policy,
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"SNS topic {resource.name} is publicly accessible",
                summary=f"Topic has public policy. Encrypted: {bool(kms_key)}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
