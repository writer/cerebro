"""Producer for detecting Secrets Manager secrets without rotation."""

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
class SecretsManagerRotationDisabledProducer(BaseAWSProducer):
    """Detect Secrets Manager secrets without automatic rotation enabled."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.secretsmanager.secret"}

    @property
    def finding_name(self) -> str:
        return "AWS: Secrets Manager Rotation Disabled"

    @property
    def rule_name(self) -> str:
        return "aws_secretsmanager_rotation_disabled"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Secrets Manager secret does not have automatic rotation enabled."

    @property
    def remediation(self) -> str:
        return (
            "Enable automatic rotation for the secret. "
            "Configure a Lambda rotation function. "
            "Set an appropriate rotation schedule (e.g., 30-90 days)."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["SC-12", "IA-5(1)"],
            "cwe": ["CWE-320", "CWE-798"],
            "cis_aws": ["2.4.1"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate secret rotation configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        rotation_enabled = data.get("rotation_enabled", False)
        if rotation_enabled:
            return findings

        last_rotated = data.get("last_rotated_date")
        last_accessed = data.get("last_accessed_date")

        risk_factors: list[str] = ["rotation_disabled"]
        if last_accessed:
            risk_factors.append("recently_accessed")

        evidence = {
            "secret_name": resource.name,
            "secret_arn": resource.external_id,
            "rotation_enabled": rotation_enabled,
            "last_rotated_date": last_rotated,
            "last_accessed_date": last_accessed,
            "rotation_lambda_arn": data.get("rotation_lambda_arn"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Secret {resource.name} does not have rotation enabled",
                summary=f"Last rotated: {last_rotated or 'never'}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
