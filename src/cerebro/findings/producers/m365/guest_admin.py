"""Producer for detecting guest users with administrative roles in M365."""

from typing import Any, Dict, List, Optional, Set

from cerebro.domain.entities import ConfigEntity, FindingEntity, ResourceEntity, Severity
from cerebro.findings.producers.base import BaseFindingProducer
from cerebro.findings.producers.registry import register_producer


@register_producer
class M365GuestAdminProducer(BaseFindingProducer):
    """Detect guest users assigned privileged directory roles."""

    @property
    def desired_sources(self) -> Set[str]:
        return {"m365"}

    @property
    def resource_types(self) -> Set[str]:
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
            "Remove the privileged directory role from the guest user or convert the account "
            "to a managed identity controlled by your organization."
        )

    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        return {
            "nist_800_53": ["AC-2", "AC-5", "AC-6"],
            "cis": ["1.1.20"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[FindingEntity]:
        findings: List[FindingEntity] = []

        data = config.normalized_config

        if not data.get("is_guest"):
            return findings

        if not data.get("account_enabled", True):
            return findings

        role_names = data.get("role_names") or []
        if not role_names:
            return findings

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        evidence = {
            "user_id": resource.external_id,
            "user_principal_name": data.get("user_principal_name"),
            "email": data.get("email"),
            "role_names": role_names,
            "directory_roles": data.get("directory_roles", []),
            "invited": data.get("created"),
            "last_login": data.get("last_login"),
            "mfa_enrolled": data.get("mfa_enrolled"),
            "risk_factors": ["guest_identity", "privileged_access"],
        }

        summary = (
            "Guest user retains administrative Microsoft 365 permissions, increasing the risk of "
            "tenant compromise through external accounts."
        )

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Guest admin user {data.get('user_principal_name') or resource.name}",
                summary=summary,
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings