"""Producer for detecting Azure Defender for Storage not enabled."""

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
class AzureDefenderStorageDisabledProducer(BaseAzureProducer):
    """Detect Azure subscriptions without Defender for Storage enabled."""

    @property
    def resource_types(self) -> set[str]:
        return {"azure.defender.pricing", "azure.security.pricing"}

    @property
    def finding_name(self) -> str:
        return "Azure: Defender for Storage Disabled"

    @property
    def rule_name(self) -> str:
        return "azure_defender_storage_disabled"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Azure Defender for Storage is not enabled for the subscription."

    @property
    def remediation(self) -> str:
        return (
            "Enable Microsoft Defender for Storage in Security Center. "
            "This provides threat detection for storage accounts including "
            "malware scanning and sensitive data exposure detection."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["SI-3", "SI-4"],
            "cwe": ["CWE-693"],
            "cis_azure": ["2.1.8"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate Defender for Storage configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        resource_type = data.get("resource_type", "").lower()
        if "storage" not in resource_type:
            return findings

        pricing_tier = data.get("pricing_tier", "").lower()
        if pricing_tier == "standard":
            return findings

        evidence = {
            "subscription_id": data.get("subscription_id"),
            "resource_type": resource_type,
            "pricing_tier": pricing_tier,
            "free_trial_remaining_time": data.get("free_trial_remaining_time"),
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title="Defender for Storage is not enabled",
                summary=f"Pricing tier: {pricing_tier or 'Free'}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
