"""Producer for detecting Okta users without MFA."""

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
from cerebro.findings.producers.utils import (
    build_identity_user_evidence,
    coerce_mapping,
    coerce_str_sequence,
    resolve_rule_id,
)

from .base import BaseOktaProducer


@register_producer
class OktaMFADisabledProducer(BaseOktaProducer):
    """Detects Okta users without MFA enabled."""

    @property
    def resource_types(self) -> set[str]:
        return {"okta.user"}

    @property
    def finding_name(self) -> str:
        return "Okta: User Without MFA"

    @property
    def rule_name(self) -> str:
        return "okta_user_without_mfa"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Okta user does not have multi-factor authentication enabled"

    @property
    def remediation(self) -> str:
        return "Enable MFA for the user or enforce organization-wide MFA policy"

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["IA-2(1)", "IA-2(2)"],
            "cwe": ["CWE-287"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate Okta user MFA configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}
        mfa_enrolled = bool(data.get("mfa_enrolled", False))
        user_status = str(data.get("status", "UNKNOWN")).upper()
        last_login = data.get("last_login")

        if user_status != "ACTIVE" or mfa_enrolled:
            return findings

        admin_roles = list(coerce_str_sequence(data.get("admin_roles")))

        risk_factors: list[str] = []
        if last_login:
            risk_factors.append("recent_login_activity")
        if admin_roles:
            risk_factors.append("has_admin_privileges")

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        profile = coerce_mapping(data.get("profile")) or {}

        evidence = build_identity_user_evidence(
            user_id=resource.external_id,
            email=data.get("email"),
            login=data.get("login"),
            status=user_status,
            mfa_enrolled=mfa_enrolled,
            last_login=last_login,
            admin_roles=admin_roles,
            risk_factors=risk_factors,
            profile=profile,
            groups=data.get("groups"),
        )

        severity = Severity.CRITICAL if admin_roles else self.severity

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Okta user {data.get('email', resource.name)} lacks MFA",
                summary=(
                    "Active Okta user without MFA enrollment. Risk factors: "
                    f"{', '.join(risk_factors) if risk_factors else 'None'}"
                ),
                evidence=evidence,
                severity=severity,
            )
        )

        return findings
