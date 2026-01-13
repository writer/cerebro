"""Producer for detecting publicly accessible Azure Functions."""

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
class AzureFunctionPublicAccessProducer(BaseAzureProducer):
    """Detect Azure Functions with public access enabled."""

    @property
    def resource_types(self) -> set[str]:
        return {"azure.function.app", "azure.web.function"}

    @property
    def finding_name(self) -> str:
        return "Azure: Function App Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "azure_function_public_access"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Azure Function App is publicly accessible from the internet."

    @property
    def remediation(self) -> str:
        return (
            "Disable public access for the Function App. "
            "Use private endpoints or VNet integration. "
            "Configure function-level authentication."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7"],
            "cwe": ["CWE-284"],
            "cis_azure": ["9.4"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate Function App for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        public_access = data.get("public_network_access", "Enabled")
        if public_access != "Enabled" and not data.get("public_access", True):
            return findings

        vnet_integration = data.get("virtual_network_subnet_id")
        private_endpoints = data.get("private_endpoint_connections", []) or []
        auth_enabled = data.get("auth_settings", {}).get("enabled", False)

        risk_factors: list[str] = ["public_access_enabled"]
        if not vnet_integration:
            risk_factors.append("no_vnet_integration")
        if not private_endpoints:
            risk_factors.append("no_private_endpoints")
        if not auth_enabled:
            risk_factors.append("auth_disabled")

        evidence = {
            "function_name": resource.name,
            "function_id": resource.external_id,
            "subscription_id": data.get("subscription_id"),
            "resource_group": data.get("resource_group"),
            "public_network_access": public_access,
            "vnet_integration": bool(vnet_integration),
            "private_endpoint_count": len(private_endpoints),
            "auth_enabled": auth_enabled,
            "runtime_version": data.get("runtime_version"),
            "default_host_name": data.get("default_host_name"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Function App {resource.name} is publicly accessible",
                summary=f"Public access: {public_access}. Auth: {auth_enabled}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
