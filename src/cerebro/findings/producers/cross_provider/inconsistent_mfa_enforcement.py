"""Producer for detecting inconsistent MFA enforcement across providers."""

from __future__ import annotations

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
    clip_sequence,
    coerce_mapping,
    resolve_rule_id,
)


@register_producer
class InconsistentMFAEnforcementProducer(BaseFindingProducer):
    """Detects users with inconsistent MFA enforcement across providers."""

    @property
    def desired_sources(self) -> set[str]:
        return {"github", "aws", "gcp", "google_workspace"}

    @property
    def resource_types(self) -> set[str]:
        return {"identity_cluster"}  # Special resource type for identity clusters

    @property
    def finding_name(self) -> str:
        return "Cross-Provider: Inconsistent MFA Enforcement"

    @property
    def rule_name(self) -> str:
        return "cross_provider_inconsistent_mfa"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "User has MFA enabled in some providers but not others"

    @property
    def remediation(self) -> str:
        return "Enable MFA consistently across all platforms for each user identity"

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["IA-2(1)", "IA-4"],
            "cwe": ["CWE-287"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        findings: list[FindingEntity] = []

        identity_data = coerce_mapping(config.normalized_config) or {}
        providers_with_mfa: list[str] = []
        providers_without_mfa: list[str] = []

        for provider in self.desired_sources:
            user_data = coerce_mapping(identity_data.get(provider)) or {}
            if not user_data:
                continue

            mfa_details = coerce_mapping(user_data.get("mfa")) or {}
            if bool(mfa_details.get("enabled")):
                providers_with_mfa.append(provider)
            else:
                providers_without_mfa.append(provider)

        if not (providers_with_mfa and providers_without_mfa):
            return findings

        total_providers = len(providers_with_mfa) + len(providers_without_mfa)
        if total_providers == 0:
            return findings

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        provider_details: dict[str, dict[str, Any]] = {}
        for provider in self.desired_sources:
            user_data = coerce_mapping(identity_data.get(provider)) or {}
            if not user_data:
                continue

            detail = {
                "username": user_data.get("username"),
                "account_type": user_data.get("account_type"),
                "last_login": user_data.get("last_login"),
                "mfa_enabled": bool(
                    (coerce_mapping(user_data.get("mfa")) or {}).get("enabled")
                ),
            }
            provider_details[provider] = detail

        evidence = {
            "identity_cluster_id": resource.external_id,
            "email": identity_data.get("email"),
            "display_name": identity_data.get("display_name"),
            "providers_with_mfa": clip_sequence(providers_with_mfa, 10),
            "providers_without_mfa": clip_sequence(providers_without_mfa, 10),
            "total_providers": total_providers,
            "mfa_coverage_percentage": round(
                len(providers_with_mfa) / total_providers * 100, 2
            ),
            "provider_details": provider_details,
        }

        title_subject = (
            identity_data.get("email") or resource.name or resource.external_id
        )
        summary = (
            "User has MFA enabled in "
            f"{len(providers_with_mfa)} providers but disabled in "
            f"{len(providers_without_mfa)} providers"
        )

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Inconsistent MFA for {title_subject}",
                summary=summary,
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
