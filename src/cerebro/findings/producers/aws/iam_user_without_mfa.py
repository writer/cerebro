"""Producer for detecting IAM users without MFA."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import coerce_mapping, resolve_rule_id

from .base import BaseAWSProducer


@register_producer
class IAMUserWithoutMFAProducer(BaseAWSProducer):
    """Detects IAM users with console access but no MFA."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.iam.user"}

    @property
    def finding_name(self) -> str:
        return "AWS: IAM User Without MFA"

    @property
    def rule_name(self) -> str:
        return "aws_iam_user_without_mfa"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "IAM user with console access does not have MFA enabled"

    @property
    def remediation(self) -> str:
        return (
            "Enable MFA for IAM users with console access or migrate access to "
            "federated roles."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "cis": ["1.2"],
            "nist_800_53": ["IA-2(1)"],
            "cwe": ["CWE-287"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate IAM user for MFA configuration."""
        findings: list[FindingEntity] = []

        normalized = config.normalized_config or {}
        console_access = bool(normalized.get("console_access", False))
        mfa_config = coerce_mapping(normalized.get("mfa")) or {}
        mfa_enabled = bool(mfa_config.get("enabled", False))
        password_last_used = normalized.get("password_last_used")
        access_keys = _coerce_sequence(normalized.get("access_keys"))

        needs_mfa = console_access or (password_last_used is not None)

        if needs_mfa and not mfa_enabled:
            rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

            risk_factors: list[str] = []
            if console_access:
                risk_factors.append("console_access_enabled")
            if password_last_used:
                risk_factors.append("password_recently_used")
            if access_keys:
                risk_factors.append("has_access_keys")

            attached_policies = _coerce_sequence(normalized.get("attached_policies"))
            is_admin = any(
                isinstance(policy, str) and "admin" in policy.lower()
                for policy in attached_policies
            )
            if is_admin:
                risk_factors.append("has_admin_privileges")

            evidence = {
                "username": resource.name,
                "user_arn": resource.external_id,
                "console_access": console_access,
                "mfa_enabled": mfa_enabled,
                "password_last_used": password_last_used,
                "access_keys_count": len(access_keys),
                "attached_policies": attached_policies,
                "groups": normalized.get("groups", []),
                "risk_factors": risk_factors,
                "user_creation_date": normalized.get("create_date"),
                "path": normalized.get("path", "/"),
            }

            severity = Severity.CRITICAL if is_admin else self.severity

            user_label = resource.name or resource.external_id
            risk_summary = ", ".join(risk_factors) if risk_factors else "None"

            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"IAM user {user_label} lacks MFA with console access",
                summary=(
                    f"IAM user {user_label} has console access but no MFA enabled. "
                    f"Risk factors: {risk_summary}"
                ),
                evidence=evidence,
                severity=severity,
            )
            findings.append(finding)

        return findings


def _coerce_sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return list(value)
    if value is None:
        return []
    return [value]
