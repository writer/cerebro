"""Producer for detecting Azure Cosmos DB accounts accessible from all networks."""

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
class AzureCosmosDBPublicNetworkProducer(BaseAzureProducer):
    """Detect Cosmos DB accounts accessible from all networks."""

    @property
    def resource_types(self) -> set[str]:
        return {"azure.cosmosdb.account", "azure.documentdb.account"}

    @property
    def finding_name(self) -> str:
        return "Azure: Cosmos DB Public Network Access"

    @property
    def rule_name(self) -> str:
        return "azure_cosmosdb_public_network"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "Azure Cosmos DB account allows access from all networks instead of "
            "selected networks only."
        )

    @property
    def remediation(self) -> str:
        return (
            "Enable virtual network filter for the Cosmos DB account. "
            "Configure virtual network rules to allow specific subnets. "
            "Use private endpoints for secure connectivity."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7"],
            "cwe": ["CWE-284"],
            "cis_azure": ["4.5.1"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate Cosmos DB network configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        vnet_filter_enabled = data.get("is_virtual_network_filter_enabled", False)
        if vnet_filter_enabled:
            return findings

        public_network_access = data.get("public_network_access", "Enabled")
        private_endpoints = data.get("private_endpoint_connections", []) or []
        ip_rules = data.get("ip_rules", []) or []
        virtual_network_rules = data.get("virtual_network_rules", []) or []

        risk_factors: list[str] = ["vnet_filter_disabled"]
        if public_network_access == "Enabled":
            risk_factors.append("public_network_enabled")
        if not private_endpoints:
            risk_factors.append("no_private_endpoints")
        if not ip_rules and not virtual_network_rules:
            risk_factors.append("no_network_restrictions")

        evidence = {
            "account_name": resource.name,
            "account_id": resource.external_id,
            "subscription_id": data.get("subscription_id"),
            "resource_group": data.get("resource_group"),
            "location": data.get("location"),
            "is_virtual_network_filter_enabled": vnet_filter_enabled,
            "public_network_access": public_network_access,
            "ip_rules_count": len(ip_rules),
            "virtual_network_rules_count": len(virtual_network_rules),
            "private_endpoint_count": len(private_endpoints),
            "database_account_offer_type": data.get("database_account_offer_type"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Cosmos DB account {resource.name} accessible from all networks",
                summary=f"VNet filter: {vnet_filter_enabled}. Public access: {public_network_access}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
