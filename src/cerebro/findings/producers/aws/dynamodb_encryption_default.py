"""Producer for detecting DynamoDB tables using default encryption."""

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
class DynamoDBEncryptionDefaultProducer(BaseAWSProducer):
    """Detect DynamoDB tables not using customer-managed KMS encryption."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.dynamodb.table"}

    @property
    def finding_name(self) -> str:
        return "AWS: DynamoDB Using Default Encryption"

    @property
    def rule_name(self) -> str:
        return "aws_dynamodb_encryption_default"

    @property
    def severity(self) -> Severity:
        return Severity.LOW

    @property
    def description(self) -> str:
        return (
            "DynamoDB table is using AWS-owned CMK (default) instead of "
            "customer-managed KMS key for encryption."
        )

    @property
    def remediation(self) -> str:
        return (
            "Enable KMS encryption with a customer-managed key. "
            "This provides more control over key rotation and access policies."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["SC-28", "SC-12"],
            "cwe": ["CWE-311"],
            "cis_aws": ["3.12"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate DynamoDB table encryption."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        encryption_type = data.get("sse_description", {}).get("SSEType") or data.get("encryption_type", "")

        if encryption_type == "KMS":
            return findings

        kms_arn = data.get("sse_description", {}).get("KMSMasterKeyArn") or data.get("kms_arn")
        pitr_enabled = data.get("point_in_time_recovery_enabled", False)
        deletion_protection = data.get("deletion_protection_enabled", False)

        risk_factors: list[str] = ["default_encryption"]
        if not pitr_enabled:
            risk_factors.append("pitr_disabled")
        if not deletion_protection:
            risk_factors.append("deletion_protection_disabled")

        evidence = {
            "table_name": resource.name,
            "table_arn": resource.external_id,
            "encryption_type": encryption_type or "DEFAULT",
            "kms_master_key_arn": kms_arn,
            "point_in_time_recovery_enabled": pitr_enabled,
            "deletion_protection_enabled": deletion_protection,
            "table_status": data.get("table_status"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"DynamoDB table {resource.name} uses default encryption",
                summary=f"Encryption: {encryption_type or 'DEFAULT'}. PITR: {pitr_enabled}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
