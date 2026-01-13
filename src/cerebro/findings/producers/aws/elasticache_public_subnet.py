"""Producer for detecting ElastiCache clusters in public subnets."""

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
class ElastiCachePublicSubnetProducer(BaseAWSProducer):
    """Detect ElastiCache clusters deployed in public subnets."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.elasticache.cluster", "aws.elasticache.replicationgroup"}

    @property
    def finding_name(self) -> str:
        return "AWS: ElastiCache in Public Subnet"

    @property
    def rule_name(self) -> str:
        return "aws_elasticache_public_subnet"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "ElastiCache cluster is deployed in a public subnet."

    @property
    def remediation(self) -> str:
        return (
            "Deploy ElastiCache clusters in private subnets only. "
            "Use VPC security groups to restrict access. "
            "Enable encryption in transit and at rest."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7"],
            "cwe": ["CWE-284"],
            "cis_aws": ["2.3.3"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate ElastiCache cluster subnet configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check for public subnet indicators
        in_public_subnet = data.get("in_public_subnet", False)
        public_subnets = data.get("public_subnets", []) or []

        if not in_public_subnet and not public_subnets:
            return findings

        engine = data.get("engine", "redis")
        transit_encryption = data.get("transit_encryption_enabled", False)
        at_rest_encryption = data.get("at_rest_encryption_enabled", False)
        auth_enabled = data.get("auth_token_enabled", False)

        risk_factors: list[str] = ["public_subnet"]
        if not transit_encryption:
            risk_factors.append("transit_encryption_disabled")
        if not at_rest_encryption:
            risk_factors.append("at_rest_encryption_disabled")
        if not auth_enabled:
            risk_factors.append("auth_disabled")

        evidence = {
            "cluster_id": resource.external_id,
            "cluster_name": resource.name,
            "engine": engine,
            "engine_version": data.get("engine_version"),
            "public_subnets": public_subnets,
            "transit_encryption_enabled": transit_encryption,
            "at_rest_encryption_enabled": at_rest_encryption,
            "auth_token_enabled": auth_enabled,
            "cache_node_type": data.get("cache_node_type"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"ElastiCache {engine} cluster {resource.name} in public subnet",
                summary=f"Public subnets: {len(public_subnets)}. Encryption: {transit_encryption}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
