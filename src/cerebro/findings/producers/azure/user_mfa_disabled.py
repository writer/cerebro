"""Producer for detecting Azure AD/Entra ID users without MFA."""

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

from .base import BaseAzureProducer


@register_producer
class AzureUserMfaProducer(BaseAzureProducer):
    """Detects Azure AD/Entra ID users without MFA enabled.

    This producer evaluates Azure AD user accounts for:
    - Missing MFA authentication methods
    - Admin accounts without MFA
    - Guest accounts without MFA
    - Users with privileged role assignments lacking MFA
    """

    @property
    def resource_types(self) -> set[str]:
        return {"azure.ad.user", "azure.entra.user"}

    @property
    def finding_name(self) -> str:
        return "Azure AD: User Without MFA"

    @property
    def rule_name(self) -> str:
        return "azure_user_without_mfa"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "Azure AD/Entra ID user does not have multi-factor authentication "
            "methods configured, increasing risk of account compromise"
        )

    @property
    def remediation(self) -> str:
        return (
            "Enable MFA for the user through Azure AD Conditional Access policies "
            "or per-user MFA settings. Ensure strong authentication methods are configured."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["IA-2(1)", "IA-2(2)", "AC-2"],
            "cwe": ["CWE-287", "CWE-308"],
            "cis_azure": ["1.1.1", "1.1.2", "1.1.3"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate Azure AD user MFA configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check if user is enabled
        account_enabled = data.get("account_enabled", True)
        if not account_enabled:
            return findings

        # Get MFA status
        strong_auth_methods = data.get("strong_authentication_methods", []) or []
        mfa_registered = len(strong_auth_methods) > 0

        # If MFA is registered, no finding
        if mfa_registered:
            return findings

        # Get user attributes
        user_principal_name = data.get("user_principal_name") or data.get("email")
        display_name = data.get("display_name")
        user_type = data.get("user_type", "Member")  # Member or Guest
        user_id = data.get("id") or resource.external_id

        # Get role assignments
        role_assignments = data.get("role_assignments", []) or []
        admin_roles = [
            r for r in role_assignments
            if self._is_admin_role(r.get("role_name", "") if isinstance(r, dict) else str(r))
        ]

        # Build risk factors
        risk_factors: list[str] = []

        if admin_roles:
            risk_factors.append("has_admin_privileges")
        if user_type == "Guest":
            risk_factors.append("guest_account")
        if data.get("sign_in_activity", {}).get("last_sign_in_date_time"):
            risk_factors.append("recent_login_activity")

        # Determine severity based on risk factors
        severity = self.severity
        if admin_roles:
            severity = Severity.CRITICAL
        elif user_type == "Guest":
            severity = Severity.HIGH

        # Build evidence
        evidence = {
            "user_id": user_id,
            "user_principal_name": user_principal_name,
            "display_name": display_name,
            "user_type": user_type,
            "account_enabled": account_enabled,
            "mfa_registered": mfa_registered,
            "strong_authentication_methods": strong_auth_methods,
            "role_assignments": [
                r.get("role_name") if isinstance(r, dict) else str(r)
                for r in role_assignments[:10]
            ],
            "admin_roles": [
                r.get("role_name") if isinstance(r, dict) else str(r)
                for r in admin_roles
            ],
            "risk_factors": risk_factors,
            "sign_in_activity": data.get("sign_in_activity"),
            "created_date_time": data.get("created_date_time"),
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        # Build title based on user type
        user_identifier = user_principal_name or display_name or user_id
        title_prefix = "Azure AD"
        if admin_roles:
            title_prefix = "Azure AD admin user"
        elif user_type == "Guest":
            title_prefix = "Azure AD guest user"

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"{title_prefix} {user_identifier} lacks MFA",
                summary=(
                    f"User without MFA ({user_type}). "
                    f"Risk factors: {', '.join(risk_factors) if risk_factors else 'None'}"
                ),
                evidence=evidence,
                severity=severity,
            )
        )

        return findings

    @staticmethod
    def _is_admin_role(role_name: str) -> bool:
        """Check if role is an administrative role."""
        admin_keywords = {
            "administrator",
            "admin",
            "global",
            "owner",
            "security",
            "privileged",
            "exchange",
            "sharepoint",
            "teams",
            "intune",
            "compliance",
            "billing",
        }
        role_lower = role_name.lower()
        return any(keyword in role_lower for keyword in admin_keywords)
