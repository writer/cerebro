"""Producer for detecting GCP Compute instances with public IPs."""

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
class GCPComputeInstancePublicIPProducer(BaseGCPProducer):
    """Detect Compute Engine instances with public IP addresses."""

    @property
    def resource_types(self) -> set[str]:
        return {"gcp.compute.instance"}

    @property
    def finding_name(self) -> str:
        return "GCP: Compute Instance Has Public IP"

    @property
    def rule_name(self) -> str:
        return "gcp_compute_instance_public_ip"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Compute Engine instance has an external (public) IP address."

    @property
    def remediation(self) -> str:
        return (
            "Remove external IP addresses from instances. "
            "Use Cloud NAT for outbound connectivity. "
            "Use Identity-Aware Proxy for SSH/RDP access."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7"],
            "cwe": ["CWE-284"],
            "cis_gcp": ["4.9"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate Compute instance for public IP."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check network interfaces for external IPs
        network_interfaces = data.get("network_interfaces", []) or []
        public_ips: list[str] = []

        for interface in network_interfaces:
            if not isinstance(interface, dict):
                continue
            access_configs = interface.get("access_configs", []) or []
            for config_item in access_configs:
                if isinstance(config_item, dict):
                    nat_ip = config_item.get("nat_ip") or config_item.get("natIP")
                    if nat_ip:
                        public_ips.append(nat_ip)

        if not public_ips:
            return findings

        # Check for service account
        service_accounts = data.get("service_accounts", []) or []
        has_sa = bool(service_accounts)

        # Check shielded VM
        shielded_config = data.get("shielded_instance_config", {}) or {}
        shielded_enabled = shielded_config.get("enable_secure_boot", False)

        risk_factors: list[str] = ["has_public_ip"]
        if has_sa:
            risk_factors.append("has_service_account")
        if not shielded_enabled:
            risk_factors.append("shielded_vm_disabled")

        evidence = {
            "instance_name": resource.name,
            "instance_id": resource.external_id,
            "project_id": data.get("project_id"),
            "zone": data.get("zone"),
            "public_ips": public_ips,
            "machine_type": data.get("machine_type"),
            "has_service_account": has_sa,
            "shielded_vm_enabled": shielded_enabled,
            "status": data.get("status"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Compute instance {resource.name} has public IP",
                summary=f"Public IPs: {', '.join(public_ips[:3])}. Service account: {has_sa}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
