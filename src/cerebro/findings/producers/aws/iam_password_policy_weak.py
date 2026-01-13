"""Producer for detecting weak IAM password policies."""

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
class IAMPasswordPolicyWeakProducer(BaseAWSProducer):
    """Detect weak IAM password policies."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.iam.password_policy", "aws.iam.account"}

    @property
    def finding_name(self) -> str:
        return "AWS: IAM Password Policy Weak"

    @property
    def rule_name(self) -> str:
        return "aws_iam_password_policy_weak"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "IAM password policy does not meet security best practices."

    @property
    def remediation(self) -> str:
        return (
            "Configure password policy with minimum length 14, "
            "require uppercase, lowercase, numbers, and symbols, "
            "enable password expiration, and prevent password reuse."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["IA-5(1)"],
            "cwe": ["CWE-521"],
            "cis_aws": ["1.8", "1.9", "1.10", "1.11"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate IAM password policy."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check policy settings
        min_length = data.get("minimum_password_length", 0)
        require_upper = data.get("require_uppercase_characters", False)
        require_lower = data.get("require_lowercase_characters", False)
        require_numbers = data.get("require_numbers", False)
        require_symbols = data.get("require_symbols", False)
        max_age = data.get("max_password_age")
        reuse_prevention = data.get("password_reuse_prevention")

        issues: list[str] = []

        if min_length < 14:
            issues.append(f"min_length_{min_length}_below_14")
        if not require_upper:
            issues.append("uppercase_not_required")
        if not require_lower:
            issues.append("lowercase_not_required")
        if not require_numbers:
            issues.append("numbers_not_required")
        if not require_symbols:
            issues.append("symbols_not_required")
        if not max_age or max_age > 90:
            issues.append("password_expiration_weak")
        if not reuse_prevention or reuse_prevention < 24:
            issues.append("password_reuse_weak")

        if not issues:
            return findings

        evidence = {
            "minimum_password_length": min_length,
            "require_uppercase_characters": require_upper,
            "require_lowercase_characters": require_lower,
            "require_numbers": require_numbers,
            "require_symbols": require_symbols,
            "max_password_age": max_age,
            "password_reuse_prevention": reuse_prevention,
            "allow_users_to_change_password": data.get("allow_users_to_change_password"),
            "hard_expiry": data.get("hard_expiry"),
            "issues": issues,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title="IAM password policy does not meet best practices",
                summary=f"Issues: {', '.join(issues[:3])}{'...' if len(issues) > 3 else ''}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
