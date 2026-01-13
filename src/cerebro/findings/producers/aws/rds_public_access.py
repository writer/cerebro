"""Producer for detecting publicly accessible RDS instances."""

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
class RDSPublicAccessProducer(BaseAWSProducer):
    """Detect RDS instances that are publicly accessible.

    Publicly accessible RDS instances expose databases to the internet,
    creating significant risk for data breaches and unauthorized access.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"aws.rds.instance", "aws.rds.cluster"}

    @property
    def finding_name(self) -> str:
        return "AWS: RDS Instance Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "aws_rds_public_access"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return (
            "RDS database instance is configured as publicly accessible, "
            "potentially exposing sensitive data to the internet."
        )

    @property
    def remediation(self) -> str:
        return (
            "Disable public accessibility for the RDS instance. "
            "Use VPC security groups to restrict access to authorized sources only. "
            "Consider using AWS PrivateLink for cross-VPC access."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7", "SC-8"],
            "cwe": ["CWE-284", "CWE-668"],
            "cis_aws": ["2.3.1"],
            "mitre_attack": ["T1190"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate RDS instance for public accessibility."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check if publicly accessible flag is set
        publicly_accessible = data.get("publicly_accessible", False)
        if not publicly_accessible:
            return findings

        # Get endpoint info
        endpoint = data.get("endpoint", {}) or {}
        address = endpoint.get("Address") or endpoint.get("address")
        port = endpoint.get("Port") or endpoint.get("port")

        # Get engine info
        engine = data.get("engine", "unknown")
        engine_version = data.get("engine_version")

        # Get security groups
        security_groups = data.get("vpc_security_groups", []) or data.get(
            "security_groups", []
        )

        # Check if in public subnet (increases severity)
        subnet_ids = data.get("db_subnet_group", {}).get("subnets", []) or []
        is_in_public_subnet = data.get("in_public_subnet", False)

        # Build risk factors
        risk_factors: list[str] = ["publicly_accessible_enabled"]

        if is_in_public_subnet:
            risk_factors.append("in_public_subnet")

        if not data.get("storage_encrypted", False):
            risk_factors.append("storage_not_encrypted")

        if not data.get("iam_database_authentication_enabled", False):
            risk_factors.append("iam_auth_not_enabled")

        # Determine severity
        severity = self.severity
        if is_in_public_subnet:
            severity = Severity.CRITICAL

        evidence = {
            "db_instance_id": resource.external_id,
            "db_instance_name": resource.name,
            "engine": engine,
            "engine_version": engine_version,
            "endpoint_address": address,
            "endpoint_port": port,
            "publicly_accessible": publicly_accessible,
            "vpc_security_groups": [
                sg.get("VpcSecurityGroupId") if isinstance(sg, dict) else sg
                for sg in security_groups[:10]
            ],
            "subnet_ids": subnet_ids[:10],
            "in_public_subnet": is_in_public_subnet,
            "storage_encrypted": data.get("storage_encrypted"),
            "iam_database_authentication_enabled": data.get(
                "iam_database_authentication_enabled"
            ),
            "multi_az": data.get("multi_az"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"RDS instance {resource.name or resource.external_id} is publicly accessible",
                summary=(
                    f"{engine} database at {address}:{port} is publicly accessible. "
                    f"Risk factors: {', '.join(risk_factors)}"
                ),
                evidence=evidence,
                severity=severity,
            )
        )

        return findings
