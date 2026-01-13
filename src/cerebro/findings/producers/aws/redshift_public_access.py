"""Producer for detecting publicly accessible Redshift clusters."""

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
class RedshiftPublicAccessProducer(BaseAWSProducer):
    """Detect Redshift clusters with public access enabled."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.redshift.cluster"}

    @property
    def finding_name(self) -> str:
        return "AWS: Redshift Cluster Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "aws_redshift_public_access"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Redshift cluster is configured for public access."

    @property
    def remediation(self) -> str:
        return (
            "Disable public accessibility for the Redshift cluster. "
            "Use VPC security groups and private subnets. "
            "Consider using PrivateLink for cross-VPC access."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7"],
            "cwe": ["CWE-284", "CWE-668"],
            "cis_aws": ["2.3.2"],
            "mitre_attack": ["T1190"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate Redshift cluster for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        publicly_accessible = data.get("publicly_accessible", False)
        if not publicly_accessible:
            return findings

        endpoint = data.get("endpoint", {})
        address = endpoint.get("Address") if isinstance(endpoint, dict) else None
        port = endpoint.get("Port") if isinstance(endpoint, dict) else None

        encrypted = data.get("encrypted", False)
        enhanced_vpc_routing = data.get("enhanced_vpc_routing", False)

        risk_factors: list[str] = ["publicly_accessible"]
        if not encrypted:
            risk_factors.append("not_encrypted")
        if not enhanced_vpc_routing:
            risk_factors.append("enhanced_vpc_routing_disabled")

        evidence = {
            "cluster_id": resource.external_id,
            "cluster_name": resource.name,
            "endpoint_address": address,
            "endpoint_port": port,
            "publicly_accessible": publicly_accessible,
            "encrypted": encrypted,
            "enhanced_vpc_routing": enhanced_vpc_routing,
            "number_of_nodes": data.get("number_of_nodes"),
            "node_type": data.get("node_type"),
            "vpc_id": data.get("vpc_id"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Redshift cluster {resource.name} is publicly accessible",
                summary=f"Endpoint: {address}:{port}. Encrypted: {encrypted}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
