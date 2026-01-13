"""Producer for detecting GCP DNS zones without DNSSEC."""

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
class GCPDNSDNSSECDisabledProducer(BaseGCPProducer):
    """Detect Cloud DNS managed zones without DNSSEC enabled."""

    @property
    def resource_types(self) -> set[str]:
        return {"gcp.dns.managedzone", "gcp.dns.zone"}

    @property
    def finding_name(self) -> str:
        return "GCP: DNS Zone DNSSEC Disabled"

    @property
    def rule_name(self) -> str:
        return "gcp_dns_dnssec_disabled"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Cloud DNS managed zone does not have DNSSEC enabled."

    @property
    def remediation(self) -> str:
        return (
            "Enable DNSSEC for the managed zone. "
            "Configure DS records with your domain registrar."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["SC-20", "SC-21"],
            "cwe": ["CWE-350"],
            "cis_gcp": ["3.3"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate DNS zone DNSSEC configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Only check public zones
        visibility = data.get("visibility", "").lower()
        if visibility == "private":
            return findings

        # Check DNSSEC config
        dnssec_config = data.get("dnssec_config", {}) or {}
        state = dnssec_config.get("state", "").lower()

        if state == "on":
            return findings

        evidence = {
            "zone_name": resource.name,
            "zone_id": resource.external_id,
            "project_id": data.get("project_id"),
            "dns_name": data.get("dns_name"),
            "visibility": visibility,
            "dnssec_state": state or "off",
            "name_servers": data.get("name_servers", [])[:4],
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"DNS zone {resource.name} does not have DNSSEC enabled",
                summary=f"Zone: {data.get('dns_name')}. DNSSEC: {state or 'off'}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
