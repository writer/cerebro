"""Producer for detecting publicly accessible OpenSearch domains."""

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


def _is_policy_public(policy: dict[str, Any] | None) -> bool:
    """Check if OpenSearch access policy allows public access."""
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
            if not condition:
                return True

    return False


@register_producer
class OpenSearchPublicAccessProducer(BaseAWSProducer):
    """Detect OpenSearch domains with public access."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.opensearch.domain", "aws.elasticsearch.domain"}

    @property
    def finding_name(self) -> str:
        return "AWS: OpenSearch Domain Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "aws_opensearch_public_access"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "OpenSearch domain is publicly accessible via access policy."

    @property
    def remediation(self) -> str:
        return (
            "Deploy the OpenSearch domain within a VPC. "
            "Restrict access policy to specific IAM principals. "
            "Enable fine-grained access control."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7"],
            "cwe": ["CWE-284", "CWE-668"],
            "cis_aws": ["4.8"],
            "mitre_attack": ["T1190"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate OpenSearch domain for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check if in VPC
        vpc_options = data.get("vpc_options", {}) or {}
        vpc_id = vpc_options.get("VPCId") or vpc_options.get("vpc_id")

        if vpc_id:
            return findings  # In VPC, not publicly accessible

        # Check access policy
        access_policy = data.get("access_policies")
        if isinstance(access_policy, str):
            import json
            try:
                access_policy = json.loads(access_policy)
            except (json.JSONDecodeError, TypeError):
                access_policy = None

        if not _is_policy_public(access_policy):
            return findings

        # Get domain details
        encryption_at_rest = data.get("encryption_at_rest_options", {}).get("Enabled", False)
        node_to_node = data.get("node_to_node_encryption_options", {}).get("Enabled", False)
        https_enforced = data.get("domain_endpoint_options", {}).get("EnforceHTTPS", False)

        risk_factors: list[str] = ["public_access_policy", "not_in_vpc"]
        if not encryption_at_rest:
            risk_factors.append("encryption_at_rest_disabled")
        if not node_to_node:
            risk_factors.append("node_to_node_encryption_disabled")
        if not https_enforced:
            risk_factors.append("https_not_enforced")

        evidence = {
            "domain_name": resource.name,
            "domain_arn": resource.external_id,
            "endpoint": data.get("endpoint"),
            "in_vpc": False,
            "encryption_at_rest": encryption_at_rest,
            "node_to_node_encryption": node_to_node,
            "https_enforced": https_enforced,
            "engine_version": data.get("engine_version"),
            "instance_type": data.get("cluster_config", {}).get("InstanceType"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"OpenSearch domain {resource.name} is publicly accessible",
                summary=f"Not in VPC with public access policy. HTTPS: {https_enforced}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
