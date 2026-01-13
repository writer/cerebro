"""Producer for detecting publicly accessible ECR repositories."""

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


def _is_ecr_policy_public(policy: dict[str, Any] | None, account_id: str | None) -> bool:
    """Check if ECR repository policy allows public access."""
    if not policy:
        return False

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal", {})

        # Check for wildcard principal
        if principal == "*":
            return True

        if isinstance(principal, dict):
            aws_principal = principal.get("AWS", [])

            if isinstance(aws_principal, str):
                aws_principal = [aws_principal]

            # Check for public AWS principal
            for p in aws_principal:
                if p == "*":
                    return True

    return False


@register_producer
class ECRPublicRepositoryProducer(BaseAWSProducer):
    """Detect ECR repositories with public access.

    Public ECR repositories expose container images to anyone,
    potentially leaking proprietary code, credentials, or vulnerabilities.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"aws.ecr.repository"}

    @property
    def finding_name(self) -> str:
        return "AWS: ECR Repository Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "aws_ecr_public_repository"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "ECR repository has a policy that allows public access to container images."
        )

    @property
    def remediation(self) -> str:
        return (
            "Update the repository policy to restrict access to specific AWS accounts. "
            "Remove wildcard (*) principals from the policy. "
            "Use private repositories and IAM policies for access control."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-3", "AC-6", "SC-7"],
            "cwe": ["CWE-284", "CWE-668"],
            "cis_aws": ["2.1.2"],
            "mitre_attack": ["T1525"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate ECR repository for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Get repository policy
        policy = data.get("policy") or data.get("repository_policy")
        if not policy:
            return findings

        # Parse policy if it's a string
        if isinstance(policy, str):
            import json
            try:
                policy = json.loads(policy)
            except (json.JSONDecodeError, TypeError):
                return findings

        # Check if policy allows public access
        account_id = data.get("account_id")
        if not _is_ecr_policy_public(policy, account_id):
            return findings

        # Get repository details
        repository_name = data.get("repository_name") or resource.name
        repository_uri = data.get("repository_uri")

        # Build risk factors
        risk_factors: list[str] = ["public_repository_policy"]

        # Check for scan on push
        scan_on_push = data.get("image_scanning_configuration", {}).get(
            "scanOnPush", False
        )
        if not scan_on_push:
            risk_factors.append("scan_on_push_disabled")

        # Check for image tag immutability
        tag_immutability = data.get("image_tag_mutability", "MUTABLE")
        if tag_immutability == "MUTABLE":
            risk_factors.append("tag_mutability_enabled")

        # Check encryption
        encryption = data.get("encryption_configuration", {})
        if encryption.get("encryptionType") != "KMS":
            risk_factors.append("not_kms_encrypted")

        evidence = {
            "repository_name": repository_name,
            "repository_arn": resource.external_id,
            "repository_uri": repository_uri,
            "scan_on_push": scan_on_push,
            "tag_immutability": tag_immutability,
            "encryption_type": encryption.get("encryptionType"),
            "policy": policy,
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"ECR repository {repository_name} is publicly accessible",
                summary=(
                    f"Repository at {repository_uri or repository_name} has public access. "
                    f"Risk factors: {', '.join(risk_factors)}"
                ),
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
