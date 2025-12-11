"""Producer for detecting inactive privileged Microsoft 365 users."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
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
class M365InactivePrivilegedUserProducer(BaseFindingProducer):
    """Identify enabled privileged users without recent sign-in activity."""

    _MAX_INACTIVITY = timedelta(days=60)

    @property
    def desired_sources(self) -> set[str]:
        return {"m365"}

    @property
    def resource_types(self) -> set[str]:
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
        return (
            "Enabled Microsoft 365 privileged account lacking recent "
            "authentication activity"
        )

    @property
    def remediation(self) -> str:
        return (
            "Disable or remove unused privileged accounts, or require "
            "re-validation and credential rotation before reactivation."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-2(4)", "AC-2(7)", "AC-6"],
            "cis": ["1.1.27"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}
        roles = coerce_mapping_sequence(data.get("directory_roles"))
        if not roles:
            return findings

        if not data.get("account_enabled", True):
            return findings

        last_login = self._parse_ts(data.get("last_login"))
        created = self._parse_ts(data.get("created"))

        if last_login and datetime.now(timezone.utc) - last_login <= self._MAX_INACTIVITY:
            return findings

        if (
            not last_login
            and created
            and datetime.now(timezone.utc) - created <= self._MAX_INACTIVITY
        ):
            return findings

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        role_names = self._resolve_role_names(data.get("role_names"), roles)

        evidence = build_identity_user_evidence(
            user_id=resource.external_id,
            user_principal_name=data.get("user_principal_name"),
            email=data.get("email"),
            role_names=role_names,
            directory_roles=roles,
            last_login=data.get("last_login"),
            created=data.get("created"),
            mfa_enrolled=data.get("mfa_enrolled"),
            risk_factors=self._build_risk_factors(
                last_login is not None,
                bool(data.get("mfa_enrolled")),
            ),
        )

        severity = Severity.CRITICAL if any(
            (name or "").lower() in {"global administrator", "company administrator"}
            for name in role_names
        ) else self.severity

        summary = (
            "Privileged Microsoft 365 account has no successful sign-in within "
            "the last 60 days while remaining enabled."
        )

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=(
                    "Dormant privileged user "
                    f"{data.get('user_principal_name') or resource.name}"
                ),
                summary=summary,
                evidence=evidence,
                severity=severity,
            )
        )

        return findings

    @staticmethod
    def _parse_ts(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            if value.endswith("Z"):
                value = value.replace("Z", "+00:00")
            return datetime.fromisoformat(value).astimezone(timezone.utc)
        except Exception:
            return None

    @staticmethod
    def _resolve_role_names(
        raw: Any,
        roles: Sequence[Mapping[str, Any]],
    ) -> list[str]:
        names = list(coerce_str_sequence(raw))
        if names:
            return names

        resolved: list[str] = []
        for role in roles:
            name = role.get("display_name")
            if isinstance(name, str) and name:
                resolved.append(name)
        return resolved

    @staticmethod
    def _build_risk_factors(has_login: bool, mfa_enabled: bool) -> list[str]:
        factors = ["privileged_access"]
        factors.append("inactive_account" if has_login else "never_signed_in")
        if not mfa_enabled:
            factors.append("no_mfa")
        return factors
