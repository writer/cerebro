"""Producer for detecting Azure NSG admin port exposure to internet."""

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

# Admin ports and their services
ADMIN_PORTS = {
    22: "SSH",
    3389: "RDP",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    23: "Telnet",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "SQLServer",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}


def _port_in_range(port: int, port_range: str | None) -> bool:
    """Check if a port falls within a port range string."""
    if not port_range:
        return False

    port_range = str(port_range).strip()

    if port_range == "*":
        return True

    if "-" in port_range:
        try:
            low, high = port_range.split("-")
            return int(low) <= port <= int(high)
        except (ValueError, TypeError):
            return False

    try:
        return int(port_range) == port
    except (ValueError, TypeError):
        return False


def _is_internet_source(source: str | None) -> bool:
    """Check if source address represents internet/any."""
    if not source:
        return False

    internet_sources = {"internet", "*", "0.0.0.0/0", "any", "::/0"}
    return str(source).lower() in internet_sources


@register_producer
class AzureNsgAdminPortExposureProducer(BaseAzureProducer):
    """Detect Azure NSG rules exposing admin ports to the internet.

    This producer checks for inbound rules that allow access from the internet
    to sensitive administrative ports like SSH (22), RDP (3389), and database ports.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"azure.network.nsg", "azure.network.security_group"}

    @property
    def finding_name(self) -> str:
        return "Azure: NSG Exposes Admin Port to Internet"

    @property
    def rule_name(self) -> str:
        return "azure_nsg_admin_port_exposure"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return (
            "Azure Network Security Group allows inbound access from the internet "
            "to administrative or sensitive ports, creating significant attack surface."
        )

    @property
    def remediation(self) -> str:
        return (
            "Restrict NSG rules to specific IP addresses or CIDR blocks. "
            "Use Azure Bastion for RDP/SSH access. "
            "Implement Just-In-Time VM access for admin ports."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7", "CM-7"],
            "cwe": ["CWE-284", "CWE-732"],
            "cis_azure": ["6.1", "6.2", "6.3"],
            "mitre_attack": ["T1190", "T1133"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate Azure NSG for admin port exposure."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        security_rules = data.get("security_rules", []) or []
        if not security_rules:
            return findings

        exposed_ports: list[dict[str, Any]] = []

        for rule in security_rules:
            if not isinstance(rule, dict):
                continue

            # Only check Allow + Inbound rules
            if rule.get("access", "").lower() != "allow":
                continue
            if rule.get("direction", "").lower() != "inbound":
                continue

            # Check if source is internet
            source = rule.get("source_address_prefix") or rule.get("source")
            if not _is_internet_source(source):
                continue

            # Check protocol (TCP or any)
            protocol = str(rule.get("protocol", "")).lower()
            if protocol not in ["tcp", "*", "any"]:
                continue

            # Check destination port range
            dest_port = rule.get("destination_port_range") or rule.get("port_range")

            for port, service in ADMIN_PORTS.items():
                if _port_in_range(port, dest_port):
                    exposed_ports.append({
                        "port": port,
                        "service": service,
                        "rule_name": rule.get("name"),
                        "rule_priority": rule.get("priority"),
                        "source": source,
                        "protocol": protocol,
                    })

        if not exposed_ports:
            return findings

        # Determine severity based on exposed ports
        severity = self.severity
        high_risk_ports = {22, 3389, 23}  # SSH, RDP, Telnet
        if any(p["port"] in high_risk_ports for p in exposed_ports):
            severity = Severity.CRITICAL

        # Build evidence
        evidence = {
            "nsg_id": resource.external_id,
            "nsg_name": resource.name,
            "subscription_id": data.get("subscription_id"),
            "resource_group": data.get("resource_group"),
            "location": data.get("location"),
            "exposed_ports": exposed_ports,
            "total_rules": len(security_rules),
            "attached_to": data.get("attached_to", []),
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        port_summary = ", ".join(
            f"{p['service']}({p['port']})" for p in exposed_ports[:5]
        )

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"NSG {resource.name} exposes admin ports to internet",
                summary=(
                    f"Exposed ports: {port_summary}. "
                    f"Total exposed: {len(exposed_ports)}. "
                    "Internet-accessible admin ports create critical attack surface."
                ),
                evidence=evidence,
                severity=severity,
            )
        )

        return findings
