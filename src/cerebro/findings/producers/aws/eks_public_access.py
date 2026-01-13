"""Producer for detecting publicly accessible EKS clusters."""

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
class EKSPublicAccessProducer(BaseAWSProducer):
    """Detect EKS clusters with public API endpoint access from 0.0.0.0/0.

    Publicly accessible EKS API endpoints expose the cluster control plane
    to attacks from the internet.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"aws.eks.cluster"}

    @property
    def finding_name(self) -> str:
        return "AWS: EKS Cluster Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "aws_eks_public_access"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "EKS cluster API endpoint is publicly accessible from any IP (0.0.0.0/0)."
        )

    @property
    def remediation(self) -> str:
        return (
            "Restrict public access CIDRs to specific IP ranges. "
            "Enable private endpoint access and disable public access if possible. "
            "Use VPC endpoints for private cluster access."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7"],
            "cwe": ["CWE-284"],
            "cis_aws": ["5.4.1"],
            "mitre_attack": ["T1190"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate EKS cluster for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        endpoint_public = data.get("endpoint_public_access", False)
        public_cidrs = data.get("public_access_cidrs", []) or []

        if not endpoint_public or "0.0.0.0/0" not in public_cidrs:
            return findings

        endpoint_private = data.get("endpoint_private_access", False)
        version = data.get("version")

        risk_factors: list[str] = ["public_endpoint_unrestricted"]
        if not endpoint_private:
            risk_factors.append("no_private_endpoint")

        evidence = {
            "cluster_name": resource.name,
            "cluster_arn": resource.external_id,
            "endpoint_public_access": endpoint_public,
            "endpoint_private_access": endpoint_private,
            "public_access_cidrs": public_cidrs,
            "version": version,
            "endpoint": data.get("endpoint"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"EKS cluster {resource.name} is publicly accessible",
                summary=f"Public CIDRs include 0.0.0.0/0. Private endpoint: {endpoint_private}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
