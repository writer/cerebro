"""Producer for detecting AWS root account usage."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
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
class IAMRootAccountUsageProducer(BaseAWSProducer):
    """Detect AWS root account usage and access key configuration.

    The AWS root account has unrestricted access to all resources and should
    rarely be used. Access keys on the root account are particularly dangerous.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"aws.iam.account", "aws.iam.credential_report"}

    @property
    def finding_name(self) -> str:
        return "AWS: Root Account Security Issue"

    @property
    def rule_name(self) -> str:
        return "aws_iam_root_account_usage"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return (
            "AWS root account has active access keys or has been used recently. "
            "Root account access should be restricted and monitored."
        )

    @property
    def remediation(self) -> str:
        return (
            "Delete root account access keys if present. "
            "Enable MFA on the root account. "
            "Use IAM users with appropriate policies for daily operations. "
            "Set up alerts for root account usage via CloudTrail."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-2", "AC-6", "IA-2"],
            "cwe": ["CWE-250", "CWE-269"],
            "cis_aws": ["1.4", "1.5", "1.6"],
            "mitre_attack": ["T1078.004"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate root account security configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check if this is root account data
        user = data.get("user", "")
        if user != "<root_account>" and not data.get("is_root", False):
            return findings

        # Check for active access keys
        access_key_1_active = str(data.get("access_key_1_active", "false")).lower() == "true"
        access_key_2_active = str(data.get("access_key_2_active", "false")).lower() == "true"

        # Check for recent usage
        password_last_used = data.get("password_last_used")
        access_key_1_last_used = data.get("access_key_1_last_used_date")
        access_key_2_last_used = data.get("access_key_2_last_used_date")

        # Check MFA status
        mfa_active = str(data.get("mfa_active", "false")).lower() == "true"

        # Build risk factors
        risk_factors: list[str] = []
        issues: list[str] = []

        if access_key_1_active:
            risk_factors.append("access_key_1_active")
            issues.append("has active access key 1")

        if access_key_2_active:
            risk_factors.append("access_key_2_active")
            issues.append("has active access key 2")

        if not mfa_active:
            risk_factors.append("mfa_not_enabled")
            issues.append("MFA not enabled")

        # Check for recent access (within 1 day)
        recent_access = False
        days_since_access = None

        for last_used in [password_last_used, access_key_1_last_used, access_key_2_last_used]:
            if last_used and last_used not in ["N/A", "no_information", "not_supported"]:
                try:
                    last_used_dt = datetime.fromisoformat(
                        str(last_used).replace("Z", "+00:00")
                    )
                    days = (datetime.now(UTC) - last_used_dt).days
                    if days_since_access is None or days < days_since_access:
                        days_since_access = days
                    if days <= 1:
                        recent_access = True
                except (ValueError, TypeError):
                    pass

        if recent_access:
            risk_factors.append("recent_usage")
            issues.append(f"used within last {days_since_access} day(s)")

        # Only create finding if there are issues
        if not risk_factors:
            return findings

        # Severity escalation
        severity = self.severity
        if access_key_1_active or access_key_2_active:
            severity = Severity.CRITICAL

        evidence = {
            "account_arn": data.get("arn"),
            "access_key_1_active": access_key_1_active,
            "access_key_2_active": access_key_2_active,
            "mfa_active": mfa_active,
            "password_last_used": password_last_used,
            "access_key_1_last_used_date": access_key_1_last_used,
            "access_key_2_last_used_date": access_key_2_last_used,
            "days_since_last_access": days_since_access,
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title="AWS root account has security issues",
                summary=f"Root account: {', '.join(issues)}",
                evidence=evidence,
                severity=severity,
            )
        )

        return findings
