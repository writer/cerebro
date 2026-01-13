"""Producer for detecting Azure Storage accounts with default network access Allow."""

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
class AzureStorageNetworkAccessAllowProducer(BaseAzureProducer):
    """Detect Storage accounts with default network access set to Allow."""

    @property
    def resource_types(self) -> set[str]:
        return {"azure.storage.account"}

    @property
    def finding_name(self) -> str:
        return "Azure: Storage Account Network Access Allow"

    @property
    def rule_name(self) -> str:
        return "azure_storage_network_access_allow"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "Azure Storage account has default network access rule set to Allow, "
            "exposing the storage to all networks."
        )

    @property
    def remediation(self) -> str:
        return (
            "Set the default network access rule to Deny. "
            "Configure virtual network rules or IP rules for authorized access. "
            "Use private endpoints for secure connectivity."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7"],
            "cwe": ["CWE-284"],
            "cis_azure": ["3.7"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate storage account network access configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        network_rule_set = data.get("network_rule_set", {}) or {}
        default_action = network_rule_set.get("default_action", "").lower()

        if default_action != "allow":
            return findings

        https_only = data.get("enable_https_traffic_only", True)
        min_tls = data.get("minimum_tls_version", "")
        private_endpoints = data.get("private_endpoint_connections", []) or []

        risk_factors: list[str] = ["default_action_allow"]
        if not https_only:
            risk_factors.append("https_not_enforced")
        if min_tls and min_tls < "TLS1_2":
            risk_factors.append("weak_tls_version")
        if not private_endpoints:
            risk_factors.append("no_private_endpoints")

        evidence = {
            "account_name": resource.name,
            "account_id": resource.external_id,
            "subscription_id": data.get("subscription_id"),
            "resource_group": data.get("resource_group"),
            "location": data.get("location"),
            "default_action": default_action,
            "virtual_network_rules": len(network_rule_set.get("virtual_network_rules", [])),
            "ip_rules": len(network_rule_set.get("ip_rules", [])),
            "enable_https_traffic_only": https_only,
            "minimum_tls_version": min_tls,
            "private_endpoint_count": len(private_endpoints),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Storage account {resource.name} allows network access from all networks",
                summary=f"Default action: Allow. Private endpoints: {len(private_endpoints)}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
