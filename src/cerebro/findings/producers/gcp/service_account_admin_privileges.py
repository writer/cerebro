"""Producer for detecting GCP service accounts with admin privileges."""

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

from .base import BaseGCPProducer

# High-privilege roles in GCP
ADMIN_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityadmin",
    "roles/resourcemanager.organizationadmin",
    "roles/resourcemanager.folderadmin",
    "roles/resourcemanager.projectiam.admin",
    "roles/compute.admin",
    "roles/storage.admin",
    "roles/cloudsql.admin",
    "roles/container.admin",
    "roles/bigquery.admin",
}


def _is_admin_role(role: str) -> bool:
    """Check if a role grants administrative privileges."""
    role_lower = role.lower()

    # Check exact matches
    if role_lower in ADMIN_ROLES:
        return True

    # Check for admin in role name
    if "admin" in role_lower:
        return True

    # Check for owner/editor primitives
    if role_lower in ["roles/owner", "roles/editor"]:
        return True

    return False


@register_producer
class GCPServiceAccountAdminPrivilegesProducer(BaseGCPProducer):
    """Detect GCP service accounts with administrative privileges.

    Service accounts with admin roles violate the principle of least privilege
    and create significant risk if compromised.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"gcp.iam.service_account", "gcp.serviceaccount"}

    @property
    def finding_name(self) -> str:
        return "GCP: Service Account Has Admin Privileges"

    @property
    def rule_name(self) -> str:
        return "gcp_service_account_admin_privileges"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "GCP service account has administrative privileges assigned. "
            "Service accounts should follow the principle of least privilege."
        )

    @property
    def remediation(self) -> str:
        return (
            "Replace admin roles with more restrictive custom roles. "
            "Use predefined roles with minimal required permissions. "
            "Implement workload identity for GKE instead of service account keys."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-2", "AC-6", "AC-6(1)"],
            "cwe": ["CWE-250", "CWE-269"],
            "cis_gcp": ["1.5", "1.6"],
            "mitre_attack": ["T1078.004"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate service account for admin privileges."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Get service account email
        email = data.get("email") or data.get("unique_id") or resource.external_id

        # Get IAM bindings/roles
        iam_bindings = data.get("iam_bindings", []) or []
        roles = data.get("roles", []) or []

        # Combine roles from different sources
        all_roles: list[str] = list(roles)
        for binding in iam_bindings:
            if isinstance(binding, dict):
                role = binding.get("role")
                if role:
                    all_roles.append(role)
            elif isinstance(binding, str):
                all_roles.append(binding)

        # Find admin roles
        admin_roles_found: list[str] = []
        for role in all_roles:
            if _is_admin_role(role):
                admin_roles_found.append(role)

        if not admin_roles_found:
            return findings

        # Check for user-managed keys (increases risk)
        has_user_managed_keys = bool(data.get("keys", []))

        # Check if default service account
        is_default_sa = (
            "compute@developer.gserviceaccount.com" in str(email)
            or "appspot.gserviceaccount.com" in str(email)
        )

        # Build risk factors
        risk_factors: list[str] = ["has_admin_privileges"]

        if "roles/owner" in admin_roles_found:
            risk_factors.append("has_owner_role")
        if "roles/editor" in admin_roles_found:
            risk_factors.append("has_editor_role")
        if has_user_managed_keys:
            risk_factors.append("has_user_managed_keys")
        if is_default_sa:
            risk_factors.append("is_default_service_account")

        # Determine severity
        severity = self.severity
        if "roles/owner" in admin_roles_found or has_user_managed_keys:
            severity = Severity.CRITICAL

        evidence = {
            "service_account_email": email,
            "service_account_id": resource.external_id,
            "display_name": data.get("display_name"),
            "project_id": data.get("project_id") or data.get("project"),
            "admin_roles": admin_roles_found,
            "all_roles": all_roles[:20],
            "has_user_managed_keys": has_user_managed_keys,
            "is_default_service_account": is_default_sa,
            "disabled": data.get("disabled", False),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Service account {email} has administrative privileges",
                summary=(
                    f"Admin roles: {', '.join(admin_roles_found[:3])}. "
                    f"Risk factors: {', '.join(risk_factors)}"
                ),
                evidence=evidence,
                severity=severity,
            )
        )

        return findings
