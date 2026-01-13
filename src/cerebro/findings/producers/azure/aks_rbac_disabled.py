"""Producer for detecting Azure AKS clusters without RBAC enabled."""

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
class AzureAKSRbacDisabledProducer(BaseAzureProducer):
    """Detect AKS clusters without RBAC enabled."""

    @property
    def resource_types(self) -> set[str]:
        return {"azure.aks.cluster", "azure.containerservice.managedcluster"}

    @property
    def finding_name(self) -> str:
        return "Azure: AKS RBAC Disabled"

    @property
    def rule_name(self) -> str:
        return "azure_aks_rbac_disabled"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "AKS cluster does not have RBAC enabled for access control."

    @property
    def remediation(self) -> str:
        return (
            "Enable RBAC on the AKS cluster. "
            "Note: RBAC cannot be enabled on existing clusters without recreation. "
            "Consider Azure AD integration for enhanced identity management."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-2", "AC-3", "AC-6"],
            "cwe": ["CWE-284"],
            "cis_azure": ["8.5"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate AKS cluster RBAC configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        rbac_enabled = data.get("enable_rbac", True)
        if rbac_enabled:
            return findings

        aad_profile = data.get("aad_profile")
        network_profile = data.get("network_profile", {})

        risk_factors: list[str] = ["rbac_disabled"]
        if not aad_profile:
            risk_factors.append("no_aad_integration")

        evidence = {
            "cluster_name": resource.name,
            "cluster_id": resource.external_id,
            "subscription_id": data.get("subscription_id"),
            "resource_group": data.get("resource_group"),
            "location": data.get("location"),
            "rbac_enabled": rbac_enabled,
            "aad_profile": bool(aad_profile),
            "kubernetes_version": data.get("kubernetes_version"),
            "network_plugin": network_profile.get("network_plugin"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"AKS cluster {resource.name} does not have RBAC enabled",
                summary=f"RBAC disabled. AAD integration: {bool(aad_profile)}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
