"""Producer for detecting guest users with administrative roles in M365."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import BaseFindingProducer, ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import (
    build_identity_user_evidence,
    coerce_mapping_sequence,
    coerce_str_sequence,
    resolve_rule_id,
)


@register_producer
class M365GuestAdminProducer(BaseFindingProducer):
    """Detect guest users assigned privileged directory roles."""

    @property
    def desired_sources(self) -> set[str]:
        return {"m365"}

    @property
    def resource_types(self) -> set[str]:
        return {"m365.user"}

    @property
    def finding_name(self) -> str:
        return "Microsoft 365: Guest User With Admin Role"

    @property
    def rule_name(self) -> str:
        return "m365_guest_admin"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Guest account holds administrative permissions in Microsoft 365"

    @property
    def remediation(self) -> str:
        return (
            "Remove the privileged directory role from the guest user or convert "
            "the account to a managed identity controlled by your organization."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-2", "AC-5", "AC-6"],
            "cis": ["1.1.20"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        if not data.get("is_guest"):
            return findings

        if not data.get("account_enabled", True):
            return findings

        role_names = self._resolve_role_names(
            data.get("role_names"),
            data.get("directory_roles"),
        )
        if not role_names:
            return findings

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        evidence = build_identity_user_evidence(
            user_id=resource.external_id,
            user_principal_name=data.get("user_principal_name"),
            email=data.get("email"),
            role_names=role_names,
            directory_roles=data.get("directory_roles"),
            created=data.get("created"),
            last_login=data.get("last_login"),
            mfa_enrolled=data.get("mfa_enrolled"),
            risk_factors=["guest_identity", "privileged_access"],
        )

        summary = (
            "Guest user retains administrative Microsoft 365 permissions, "
            "increasing the risk of tenant compromise through external accounts."
        )

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=(
                    "Guest admin user "
                    f"{data.get('user_principal_name') or resource.name}"
                ),
                summary=summary,
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings

    @staticmethod
    def _resolve_role_names(raw: Any, roles_value: Any) -> list[str]:
        names = list(coerce_str_sequence(raw))
        if names:
            return names

        directory_roles = coerce_mapping_sequence(roles_value)
        if directory_roles:
            resolved: list[str] = []
            for entry in directory_roles:
                name = entry.get("display_name")
                if isinstance(name, str) and name:
                    resolved.append(name)
            if resolved:
                return resolved
        return []
