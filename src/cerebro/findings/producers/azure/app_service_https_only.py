"""Producer for detecting Azure App Service without HTTPS-only."""

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
class AzureAppServiceHTTPSOnlyProducer(BaseAzureProducer):
    """Detect App Service without HTTPS-only configuration."""

    @property
    def resource_types(self) -> set[str]:
        return {"azure.app.service", "azure.web.app", "azure.appservice.webapp"}

    @property
    def finding_name(self) -> str:
        return "Azure: App Service HTTP Not Redirected to HTTPS"

    @property
    def rule_name(self) -> str:
        return "azure_app_service_https_only"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Azure App Service does not redirect HTTP to HTTPS."

    @property
    def remediation(self) -> str:
        return (
            "Enable HTTPS Only in the App Service TLS/SSL settings. "
            "This forces all HTTP traffic to redirect to HTTPS."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["SC-8", "SC-23"],
            "cwe": ["CWE-319"],
            "cis_azure": ["9.2"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate App Service HTTPS configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        https_only = data.get("https_only", False)
        if https_only:
            return findings

        min_tls = data.get("min_tls_version", "")
        client_cert_enabled = data.get("client_cert_enabled", False)

        risk_factors: list[str] = ["https_not_enforced"]
        if min_tls and min_tls < "1.2":
            risk_factors.append("weak_tls_version")
        if not client_cert_enabled:
            risk_factors.append("client_certs_disabled")

        evidence = {
            "app_name": resource.name,
            "app_id": resource.external_id,
            "subscription_id": data.get("subscription_id"),
            "resource_group": data.get("resource_group"),
            "https_only": https_only,
            "min_tls_version": min_tls,
            "client_cert_enabled": client_cert_enabled,
            "state": data.get("state"),
            "default_host_name": data.get("default_host_name"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"App Service {resource.name} does not enforce HTTPS",
                summary=f"HTTPS only: {https_only}. Min TLS: {min_tls or 'default'}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
