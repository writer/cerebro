"""Producer for detecting inactive privileged Microsoft 365 users."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from cerebro.domain.entities import ConfigEntity, FindingEntity, ResourceEntity, Severity
from cerebro.findings.producers.base import BaseFindingProducer
from cerebro.findings.producers.registry import register_producer


@register_producer
class M365InactivePrivilegedUserProducer(BaseFindingProducer):
    """Identify enabled privileged users without recent sign-in activity."""

    _MAX_INACTIVITY = timedelta(days=60)

    @property
    def desired_sources(self) -> Set[str]:
        return {"m365"}

    @property
    def resource_types(self) -> Set[str]:
        return {"m365.user"}

    @property
    def finding_name(self) -> str:
        return "Microsoft 365: Dormant Privileged Account"

    @property
    def rule_name(self) -> str:
        return "m365_admin_inactive"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Enabled Microsoft 365 privileged account lacking recent authentication activity"

    @property
    def remediation(self) -> str:
        return (
            "Disable or remove unused privileged accounts, or require re-validation and credential "
            "rotation before reactivation."
        )

    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        return {
            "nist_800_53": ["AC-2(4)", "AC-2(7)", "AC-6"],
            "cis": ["1.1.27"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[FindingEntity]:
        findings: List[FindingEntity] = []

        data = config.normalized_config
        roles = data.get("directory_roles") or []
        if not roles:
            return findings

        if not data.get("account_enabled", True):
            return findings

        last_login = self._parse_ts(data.get("last_login"))
        created = self._parse_ts(data.get("created"))

        if last_login and datetime.now(timezone.utc) - last_login <= self._MAX_INACTIVITY:
            return findings

        if not last_login and created and datetime.now(timezone.utc) - created <= self._MAX_INACTIVITY:
            return findings

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        role_names = data.get("role_names") or [role.get("display_name") for role in roles if role.get("display_name")]

        evidence = {
            "user_id": resource.external_id,
            "user_principal_name": data.get("user_principal_name"),
            "email": data.get("email"),
            "role_names": role_names,
            "directory_roles": roles,
            "last_login": data.get("last_login"),
            "created": data.get("created"),
            "mfa_enrolled": data.get("mfa_enrolled"),
            "risk_factors": [
                "privileged_access",
                "inactive_account" if last_login else "never_signed_in",
                "no_mfa" if not data.get("mfa_enrolled") else "",
            ],
        }
        evidence["risk_factors"] = [factor for factor in evidence["risk_factors"] if factor]

        severity = Severity.CRITICAL if any(
            (name or "").lower() in {"global administrator", "company administrator"}
            for name in role_names
        ) else self.severity

        summary = (
            "Privileged Microsoft 365 account has no successful sign-in within the last 60 days "
            "while remaining enabled."
        )

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Dormant privileged user {data.get('user_principal_name') or resource.name}",
                summary=summary,
                evidence=evidence,
                severity=severity,
            )
        )

        return findings

    @staticmethod
    def _parse_ts(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            if value.endswith("Z"):
                value = value.replace("Z", "+00:00")
            return datetime.fromisoformat(value).astimezone(timezone.utc)
        except Exception:
            return None
