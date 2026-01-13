"""Producer for detecting AWS accounts without CloudTrail enabled."""

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
class CloudTrailNotEnabledProducer(BaseAWSProducer):
    """Detect AWS CloudTrail trails that are not logging or properly configured.

    CloudTrail is essential for security auditing and incident response.
    All trails should be enabled, multi-region, and encrypted.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"aws.cloudtrail.trail"}

    @property
    def finding_name(self) -> str:
        return "AWS: CloudTrail Not Properly Configured"

    @property
    def rule_name(self) -> str:
        return "aws_cloudtrail_not_enabled"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "AWS CloudTrail trail is not logging, not multi-region, or lacks "
            "proper security configurations like encryption and log validation."
        )

    @property
    def remediation(self) -> str:
        return (
            "Enable logging on the CloudTrail trail. "
            "Configure multi-region trails for comprehensive coverage. "
            "Enable KMS encryption and log file validation."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AU-2", "AU-3", "AU-6", "AU-12"],
            "cwe": ["CWE-778"],
            "cis_aws": ["3.1", "3.2", "3.5", "3.7"],
            "mitre_attack": ["T1562.008"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate CloudTrail configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check trail status
        is_logging = data.get("is_logging", False)
        is_multi_region = data.get("is_multi_region_trail", False)
        kms_key_id = data.get("kms_key_id")
        log_file_validation = data.get("log_file_validation_enabled", False)
        include_global_events = data.get("include_global_service_events", False)

        # Build list of issues
        issues: list[str] = []
        risk_factors: list[str] = []

        if not is_logging:
            issues.append("not logging")
            risk_factors.append("logging_disabled")

        if not is_multi_region:
            issues.append("not multi-region")
            risk_factors.append("single_region")

        if not kms_key_id:
            issues.append("not KMS encrypted")
            risk_factors.append("no_encryption")

        if not log_file_validation:
            issues.append("no log validation")
            risk_factors.append("no_log_validation")

        if not include_global_events:
            issues.append("excludes global events")
            risk_factors.append("no_global_events")

        # Only create finding if there are issues
        if not issues:
            return findings

        # Determine severity based on issues
        severity = Severity.MEDIUM
        if not is_logging:
            severity = Severity.CRITICAL
        elif not is_multi_region or not kms_key_id:
            severity = Severity.HIGH

        evidence = {
            "trail_name": resource.name,
            "trail_arn": resource.external_id,
            "is_logging": is_logging,
            "is_multi_region": is_multi_region,
            "kms_key_id": kms_key_id,
            "log_file_validation_enabled": log_file_validation,
            "include_global_service_events": include_global_events,
            "s3_bucket_name": data.get("s3_bucket_name"),
            "cloudwatch_logs_log_group_arn": data.get("cloud_watch_logs_log_group_arn"),
            "issues": issues,
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"CloudTrail {resource.name} has configuration issues",
                summary=f"Issues: {', '.join(issues)}",
                evidence=evidence,
                severity=severity,
            )
        )

        return findings
