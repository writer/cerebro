"""Producer for detecting GitHub admin users without 2FA."""

from __future__ import annotations

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
    resolve_rule_id,
)

from .base import BaseGitHubProducer


@register_producer
class AdminWithout2FAProducer(BaseGitHubProducer):
    """Detects GitHub admin users without 2FA enabled."""

    @property
    def resource_types(self) -> set[str]:
        return {"github.user"}  # Note: this would need to be added to GitHub provider

    @property
    def finding_name(self) -> str:
        return "GitHub: Admin User Without 2FA"

    @property
    def rule_name(self) -> str:
        return "github_admin_without_2fa"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "GitHub admin user does not have two-factor authentication enabled"

    @property
    def remediation(self) -> str:
        return (
            "Enable two-factor authentication for all admin users in GitHub "
            "organization settings."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "cis": ["5.1.1"],
            "nist_800_53": ["IA-2(1)"],
            "cwe": ["CWE-287"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate GitHub user for 2FA configuration."""
        findings: list[FindingEntity] = []

        normalized = config.normalized_config or {}
        is_admin = bool(normalized.get("is_admin", False))
        has_2fa = bool(normalized.get("two_factor_authentication", False))
        is_human = normalized.get("type") == "User"

        if is_admin and not has_2fa and is_human:
            rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

            evidence = build_identity_user_evidence(
                user_id=resource.external_id,
                username=resource.name,
                two_factor_authentication=has_2fa,
                account_type=normalized.get("type"),
                metadata={
                    "site_admin": normalized.get("site_admin", False),
                    "profile_url": normalized.get("html_url"),
                    "last_seen": config.captured_at.isoformat(),
                },
                risk_factors=["admin_privileges", "mfa_disabled"],
                extra={"is_admin": is_admin},
            )
            title = f"GitHub admin user {resource.name} lacks 2FA"
            summary = (
                f"Admin user {resource.name} has administrative privileges but does "
                "not have two-factor authentication enabled."
            )

            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=title,
                summary=summary,
                evidence=evidence,
                severity=self.severity,
            )
            findings.append(finding)

        return findings
