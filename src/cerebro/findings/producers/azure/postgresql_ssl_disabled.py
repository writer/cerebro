"""Producer for detecting Azure PostgreSQL without SSL enforcement."""

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
class AzurePostgreSQLSSLDisabledProducer(BaseAzureProducer):
    """Detect Azure PostgreSQL servers without SSL enforcement."""

    @property
    def resource_types(self) -> set[str]:
        return {"azure.postgresql.server", "azure.dbforpostgresql.server"}

    @property
    def finding_name(self) -> str:
        return "Azure: PostgreSQL SSL Not Enforced"

    @property
    def rule_name(self) -> str:
        return "azure_postgresql_ssl_disabled"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Azure Database for PostgreSQL does not enforce SSL connections."

    @property
    def remediation(self) -> str:
        return (
            "Enable SSL enforcement for the PostgreSQL server. "
            "Configure minimum TLS version to 1.2."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["SC-8", "SC-23"],
            "cwe": ["CWE-319"],
            "cis_azure": ["4.3.1"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate PostgreSQL SSL configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        ssl_enforcement = data.get("ssl_enforcement", "").lower()
        if ssl_enforcement == "enabled":
            return findings

        min_tls = data.get("minimal_tls_version", "")
        geo_redundant = data.get("geo_redundant_backup_enabled", False)

        risk_factors: list[str] = ["ssl_not_enforced"]
        if min_tls and min_tls < "TLS1_2":
            risk_factors.append("weak_tls_version")
        if not geo_redundant:
            risk_factors.append("geo_redundant_backup_disabled")

        evidence = {
            "server_name": resource.name,
            "server_id": resource.external_id,
            "subscription_id": data.get("subscription_id"),
            "resource_group": data.get("resource_group"),
            "ssl_enforcement": ssl_enforcement,
            "minimal_tls_version": min_tls,
            "version": data.get("version"),
            "sku_tier": data.get("sku", {}).get("tier"),
            "geo_redundant_backup_enabled": geo_redundant,
            "public_network_access": data.get("public_network_access"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"PostgreSQL server {resource.name} does not enforce SSL",
                summary=f"SSL: {ssl_enforcement or 'disabled'}. Min TLS: {min_tls or 'not set'}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
