"""Producer for detecting Azure SQL Server with unrestricted public access."""

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
class AzureSQLServerPublicAccessProducer(BaseAzureProducer):
    """Detect Azure SQL Server with unrestricted public access.

    SQL Servers with firewall rules allowing 0.0.0.0-255.255.255.255
    are exposed to the entire internet.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"azure.sql.server", "azure.sqlserver"}

    @property
    def finding_name(self) -> str:
        return "Azure: SQL Server Unrestricted Public Access"

    @property
    def rule_name(self) -> str:
        return "azure_sqlserver_public_access"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return (
            "Azure SQL Server has firewall rules allowing access from any IP address "
            "(0.0.0.0-255.255.255.255), exposing the database to the internet."
        )

    @property
    def remediation(self) -> str:
        return (
            "Remove overly permissive firewall rules. "
            "Restrict access to specific IP ranges or Azure services. "
            "Use Private Endpoints for secure connectivity."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7", "SC-8"],
            "cwe": ["CWE-284", "CWE-668"],
            "cis_azure": ["4.1.2"],
            "mitre_attack": ["T1190"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate SQL Server firewall rules for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Get firewall rules
        firewall_rules = data.get("firewall_rules", []) or []

        # Check for unrestricted access
        public_rules: list[dict[str, Any]] = []

        for rule in firewall_rules:
            if not isinstance(rule, dict):
                continue

            start_ip = rule.get("start_ip_address") or rule.get("startIpAddress", "")
            end_ip = rule.get("end_ip_address") or rule.get("endIpAddress", "")
            rule_name = rule.get("name", "")

            # Check for full internet access (0.0.0.0 - 255.255.255.255)
            if start_ip == "0.0.0.0" and end_ip == "255.255.255.255":
                public_rules.append({
                    "name": rule_name,
                    "start_ip": start_ip,
                    "end_ip": end_ip,
                    "type": "full_internet",
                })
            # Check for Azure services access (0.0.0.0 - 0.0.0.0)
            elif start_ip == "0.0.0.0" and end_ip == "0.0.0.0":
                # This allows Azure services - note but don't flag as critical
                pass

        if not public_rules:
            return findings

        # Build risk factors
        risk_factors: list[str] = ["unrestricted_firewall_rules"]

        # Check auditing status
        if not data.get("auditing_enabled", False):
            risk_factors.append("auditing_disabled")

        # Check TDE status
        if not data.get("tde_enabled", True):
            risk_factors.append("tde_disabled")

        # Check for Defender
        if not data.get("defender_enabled", False):
            risk_factors.append("defender_disabled")

        # Check AAD admin
        if not data.get("aad_admin_configured", False):
            risk_factors.append("no_aad_admin")

        evidence = {
            "server_name": resource.name,
            "server_id": resource.external_id,
            "subscription_id": data.get("subscription_id"),
            "resource_group": data.get("resource_group"),
            "location": data.get("location"),
            "public_firewall_rules": public_rules,
            "total_firewall_rules": len(firewall_rules),
            "auditing_enabled": data.get("auditing_enabled"),
            "tde_enabled": data.get("tde_enabled"),
            "defender_enabled": data.get("defender_enabled"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"SQL Server {resource.name} allows unrestricted public access",
                summary=(
                    f"Found {len(public_rules)} rule(s) allowing 0.0.0.0-255.255.255.255. "
                    f"Risk factors: {', '.join(risk_factors)}"
                ),
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
