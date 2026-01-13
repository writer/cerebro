"""Producer for detecting GCP firewall admin port exposure to internet."""

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


def _port_in_range(port: int, port_spec: str) -> bool:
    """Check if a port falls within a GCP port specification."""
    if not port_spec:
        return False

    port_spec = str(port_spec).strip()

    if "-" in port_spec:
        try:
            low, high = port_spec.split("-")
            return int(low) <= port <= int(high)
        except (ValueError, TypeError):
            return False

    try:
        return int(port_spec) == port
    except (ValueError, TypeError):
        return False


def _check_allowed_rules(allowed_rules: list[dict[str, Any]], port: int) -> bool:
    """Check if port is allowed by any firewall rule."""
    for rule in allowed_rules:
        if not isinstance(rule, dict):
            continue

        protocol = rule.get("IPProtocol", "").lower()

        # Protocol "all" allows everything
        if protocol == "all":
            return True

        # Only TCP matters for admin ports
        if protocol != "tcp":
            continue

        # No ports specified means all ports
        ports = rule.get("ports")
        if ports is None:
            return True

        # Check each port specification
        if isinstance(ports, list):
            for port_spec in ports:
                if _port_in_range(port, port_spec):
                    return True
        elif _port_in_range(port, str(ports)):
            return True

    return False


@register_producer
class GCPFirewallAdminPortExposureProducer(BaseGCPProducer):
    """Detect GCP firewall rules exposing admin ports to the internet.

    This producer checks for INGRESS firewall rules with source range 0.0.0.0/0
    that allow access to sensitive administrative ports like SSH and RDP.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"gcp.compute.firewall", "gcp.firewall.rule"}

    @property
    def finding_name(self) -> str:
        return "GCP: Firewall Exposes Admin Port to Internet"

    @property
    def rule_name(self) -> str:
        return "gcp_firewall_admin_port_exposure"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return (
            "GCP firewall rule allows inbound access from the internet (0.0.0.0/0) "
            "to administrative or sensitive ports, creating significant attack surface."
        )

    @property
    def remediation(self) -> str:
        return (
            "Restrict firewall source ranges to specific IP addresses or CIDR blocks. "
            "Use Identity-Aware Proxy (IAP) for SSH/RDP access. "
            "Implement OS Login for managed SSH access to VMs."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7", "CM-7"],
            "cwe": ["CWE-284", "CWE-732"],
            "cis_gcp": ["3.6", "3.7"],
            "mitre_attack": ["T1190", "T1133"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate GCP firewall rule for admin port exposure."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Only check INGRESS rules
        direction = data.get("direction", "").upper()
        if direction != "INGRESS":
            return findings

        # Check source ranges for 0.0.0.0/0
        source_ranges = data.get("source_ranges", []) or []
        if "0.0.0.0/0" not in source_ranges and "::/0" not in source_ranges:
            return findings

        # Check allowed rules for admin ports
        allowed_rules = data.get("allowed", []) or data.get("allowed_rules", []) or []
        if not allowed_rules:
            return findings

        exposed_ports: list[dict[str, Any]] = []

        for port, service in ADMIN_PORTS.items():
            if _check_allowed_rules(allowed_rules, port):
                exposed_ports.append({
                    "port": port,
                    "service": service,
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
            "firewall_id": resource.external_id,
            "firewall_name": resource.name,
            "project_id": data.get("project_id") or data.get("project"),
            "network": data.get("network"),
            "direction": direction,
            "source_ranges": source_ranges,
            "allowed_rules": allowed_rules,
            "exposed_ports": exposed_ports,
            "priority": data.get("priority"),
            "disabled": data.get("disabled", False),
            "target_tags": data.get("target_tags", []),
            "target_service_accounts": data.get("target_service_accounts", []),
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        port_summary = ", ".join(
            f"{p['service']}({p['port']})" for p in exposed_ports[:5]
        )

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Firewall {resource.name} exposes admin ports to internet",
                summary=(
                    f"Exposed ports: {port_summary}. "
                    f"Source: 0.0.0.0/0. "
                    "Internet-accessible admin ports create critical attack surface."
                ),
                evidence=evidence,
                severity=severity,
            )
        )

        return findings
