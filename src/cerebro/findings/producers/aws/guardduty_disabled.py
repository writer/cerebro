"""Producer for detecting AWS accounts without GuardDuty enabled."""

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
class GuardDutyDisabledProducer(BaseAWSProducer):
    """Detect regions/accounts without GuardDuty enabled."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.guardduty.detector", "aws.account"}

    @property
    def finding_name(self) -> str:
        return "AWS: GuardDuty Not Enabled"

    @property
    def rule_name(self) -> str:
        return "aws_guardduty_disabled"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "AWS GuardDuty is not enabled or is suspended."

    @property
    def remediation(self) -> str:
        return (
            "Enable GuardDuty in all regions. "
            "Configure GuardDuty to publish findings to Security Hub. "
            "Enable S3, EKS, and Malware protection features."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["SI-4", "IR-4"],
            "cwe": ["CWE-778"],
            "cis_aws": ["4.1"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate GuardDuty configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        enabled = data.get("enabled", False) or data.get("enabled_in_account", False)
        status = data.get("status")

        if enabled and status not in [None, False, "DISABLED"]:
            return findings

        # Get feature status
        s3_protection = data.get("s3_protection_enabled", False)
        eks_protection = data.get("eks_audit_log_enabled", False)
        malware_protection = data.get("malware_protection_enabled", False)

        risk_factors: list[str] = []
        if not enabled:
            risk_factors.append("guardduty_not_enabled")
        elif status in [None, False, "DISABLED"]:
            risk_factors.append("guardduty_suspended")

        evidence = {
            "detector_id": resource.external_id,
            "region": data.get("region"),
            "enabled": enabled,
            "status": status,
            "s3_protection_enabled": s3_protection,
            "eks_audit_log_enabled": eks_protection,
            "malware_protection_enabled": malware_protection,
            "finding_publishing_frequency": data.get("finding_publishing_frequency"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"GuardDuty is not enabled in {data.get('region', 'region')}",
                summary=f"Enabled: {enabled}. Status: {status or 'not configured'}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
