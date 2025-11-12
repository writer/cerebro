"""Producer for detecting dormant Okta admin accounts."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
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
    clip_sequence,
    coerce_str_sequence,
    resolve_rule_id,
)

from .base import BaseOktaProducer


@register_producer
class OktaDormantAdminProducer(BaseOktaProducer):
    """Detect active Okta admins without recent sign-in activity."""

    _MAX_INACTIVITY = timedelta(days=60)

    @property
    def resource_types(self) -> set[str]:
        return {"okta.user"}

    @property
    def finding_name(self) -> str:
        return "Okta: Dormant Admin Account"

    @property
    def rule_name(self) -> str:
        return "okta_admin_inactive"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Active Okta administrator without any recent successful sign-in"

    @property
    def remediation(self) -> str:
        return (
            "Review the administrator account, disable it if unused, or rotate "
            "the credentials after validating the owner's need for access."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-2(4)", "AC-2(5)", "IA-4"],
            "cis": ["1.1.10"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}
        status = str(data.get("status", "")).upper()
        if status not in {"ACTIVE"}:
            return findings

        admin_roles = list(coerce_str_sequence(data.get("admin_roles")))
        if not admin_roles:
            return findings

        if data.get("is_service_account"):
            return findings

        last_login = self._parse_timestamp(data.get("last_login"))
        if last_login:
            if datetime.now(UTC) - last_login <= self._MAX_INACTIVITY:
                return findings
        else:
            created = self._parse_timestamp(data.get("created"))
            if created and datetime.now(UTC) - created <= self._MAX_INACTIVITY:
                return findings

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        evidence = {
            "user_id": resource.external_id,
            "login": data.get("login"),
            "email": data.get("email"),
            "admin_roles": admin_roles,
            "last_login": data.get("last_login"),
            "created": data.get("created"),
            "status": status,
            "mfa_enrolled": data.get("mfa_enrolled"),
            "applications": clip_sequence(data.get("applications")),
            "groups": clip_sequence(data.get("groups")),
            "risk_factors": [
                "admin_privileges",
                "no_recent_login" if last_login else "never_logged_in",
            ],
        }

        summary = (
            "Okta administrator without sign-in activity for more than 60 days "
            "remains enabled."
        )

        severity = (
            Severity.CRITICAL
            if any("SUPER" in role.upper() for role in admin_roles)
            else self.severity
        )

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=(
                    f"Okta admin {data.get('login') or resource.name} is inactive"
                ),
                summary=summary,
                evidence=evidence,
                severity=severity,
            )
        )

        return findings

    @staticmethod
    def _parse_timestamp(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            if value.endswith("Z"):
                value = value.replace("Z", "+00:00")
            return datetime.fromisoformat(value).astimezone(UTC)
        except Exception:
            return None
