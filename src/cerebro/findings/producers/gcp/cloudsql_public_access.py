"""Producer for detecting publicly accessible GCP Cloud SQL instances."""

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

from .base import BaseGCPProducer


@register_producer
class CloudSQLPublicAccessProducer(BaseGCPProducer):
    """Detect Cloud SQL instances with public IP access from 0.0.0.0/0.

    Cloud SQL instances that whitelist all public IP addresses (0.0.0.0/0)
    are exposed to attacks from any source on the internet.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"gcp.cloudsql.instance", "gcp.sql.instance"}

    @property
    def finding_name(self) -> str:
        return "GCP: Cloud SQL Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "gcp_cloudsql_public_access"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return (
            "Cloud SQL instance has authorized networks configured to allow "
            "access from all public IP addresses (0.0.0.0/0)."
        )

    @property
    def remediation(self) -> str:
        return (
            "Remove the 0.0.0.0/0 authorized network entry. "
            "Restrict access to specific IP addresses or CIDR ranges. "
            "Use Cloud SQL Auth Proxy or private IP for secure connections."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7", "SC-8"],
            "cwe": ["CWE-284", "CWE-668"],
            "cis_gcp": ["6.2", "6.5"],
            "mitre_attack": ["T1190"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate Cloud SQL instance for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Get authorized networks
        authorized_networks = data.get("authorized_networks", []) or []
        ip_configuration = data.get("ip_configuration", {}) or {}

        # Also check nested structure
        if not authorized_networks and ip_configuration:
            authorized_networks = ip_configuration.get("authorized_networks", []) or []

        # Check for 0.0.0.0/0
        public_access_entries: list[dict[str, Any]] = []
        for network in authorized_networks:
            if isinstance(network, dict):
                value = network.get("value") or network.get("cidr")
            else:
                value = str(network)

            if value in ["0.0.0.0/0", "::/0"]:
                public_access_entries.append({
                    "name": network.get("name") if isinstance(network, dict) else None,
                    "value": value,
                })

        if not public_access_entries:
            return findings

        # Get database details
        database_version = data.get("database_version") or data.get("version")
        instance_type = data.get("instance_type")
        region = data.get("region") or data.get("location")

        # Check SSL requirement
        require_ssl = ip_configuration.get("require_ssl", False)

        # Check for private IP
        private_ip = ip_configuration.get("private_network")
        has_private_ip = bool(private_ip)

        # Build risk factors
        risk_factors: list[str] = ["public_ip_whitelisted_all"]

        if not require_ssl:
            risk_factors.append("ssl_not_required")

        if not has_private_ip:
            risk_factors.append("no_private_ip")

        evidence = {
            "instance_name": resource.name,
            "instance_id": resource.external_id,
            "project_id": data.get("project_id") or data.get("project"),
            "database_version": database_version,
            "instance_type": instance_type,
            "region": region,
            "public_access_entries": public_access_entries,
            "authorized_networks_count": len(authorized_networks),
            "require_ssl": require_ssl,
            "has_private_ip": has_private_ip,
            "ip_addresses": data.get("ip_addresses", []),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Cloud SQL {resource.name} allows access from any IP",
                summary=(
                    f"{database_version or 'Database'} instance allows 0.0.0.0/0. "
                    f"SSL required: {require_ssl}. "
                    f"Risk factors: {', '.join(risk_factors)}"
                ),
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
