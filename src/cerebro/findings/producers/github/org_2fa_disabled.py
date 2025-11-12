"""Producer for detecting GitHub organizations with 2FA disabled."""

from __future__ import annotations

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import coerce_mapping, resolve_rule_id

from .base import BaseGitHubProducer


@register_producer
class Org2FADisabledProducer(BaseGitHubProducer):
    """Detects GitHub organizations that do not enforce 2FA."""

    @property
    def resource_types(self) -> set[str]:
        return {"github.org"}

    @property
    def finding_name(self) -> str:
        return "GitHub: Organization 2FA Not Enforced"

    @property
    def rule_name(self) -> str:
        return "github_org_2fa_disabled"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "GitHub organization does not enforce two-factor authentication for "
            "members."
        )

    @property
    def remediation(self) -> str:
        return (
            "Go to Organization Settings > Authentication security and enable "
            "'Require two-factor authentication for everyone in the organization'."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "cis": ["5.1.1"],
            "nist_800_53": ["IA-2(1)", "AC-2"],
            "cwe": ["CWE-287"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate GitHub organization 2FA enforcement."""
        findings: list[FindingEntity] = []

        normalized = config.normalized_config or {}
        requires_2fa = bool(normalized.get("two_factor_requirement_enabled", False))
        member_count = (
            int(normalized.get("public_members", 0))
            + int(normalized.get("private_members", 0))
        )

        if not requires_2fa and member_count > 0:
            rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

            plan = coerce_mapping(normalized.get("plan")) or {}
            evidence = {
                "organization": resource.name,
                "login": resource.external_id,
                "two_factor_requirement_enabled": requires_2fa,
                "total_members": member_count,
                "public_members": normalized.get("public_members", 0),
                "private_members": normalized.get("private_members", 0),
                "billing_email": normalized.get("billing_email"),
                "plan": plan.get("name"),
                "created_at": normalized.get("created_at"),
                "updated_at": normalized.get("updated_at"),
            }
            summary = (
                f"Organization {resource.name} with {member_count} members does not "
                "require two-factor authentication."
            )

            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"GitHub organization {resource.name} does not enforce 2FA",
                summary=summary,
                evidence=evidence,
                severity=self.severity,
            )
            findings.append(finding)

        return findings
