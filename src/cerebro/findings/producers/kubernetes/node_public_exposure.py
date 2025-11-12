"""Detect Kubernetes nodes with public exposure."""

from __future__ import annotations

import ipaddress
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import BaseFindingProducer
from cerebro.findings.producers.registry import register_producer


def _is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
    )


@register_producer
class K8sNodePublicExposureProducer(BaseFindingProducer):
    """Detect nodes that have public-facing IP addresses or hostnames."""

    @property
    def desired_sources(self) -> set[str]:
        return {"kubernetes"}

    @property
    def resource_types(self) -> set[str]:
        return {"k8s.node"}

    @property
    def finding_name(self) -> str:
        return "Kubernetes node exposes public network endpoints"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def rule_name(self) -> str:
        return "k8s_node_public_exposure"

    @property
    def description(self) -> str:
        return "Node has public IP or hostname that can be directly reached"

    @property
    def remediation(self) -> str:
        return (
            "Remove public IP assignments from Kubernetes nodes or place them behind "
            "firewalls, and ensure workloads are fronted by secure ingress layers."
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: dict[str, Any] | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        addresses = normalized.get("addresses") or []

        exposures: list[dict[str, Any]] = []

        for address in addresses:
            addr_type = (address.get("type") or "").upper()
            value = address.get("address")

            if addr_type == "EXTERNALIP" and _is_public_ip(value):
                exposures.append(
                    {
                        "type": "external_ip",
                        "address": value,
                        "public": True,
                    }
                )
            elif addr_type == "HOSTNAME" and value:
                exposures.append(
                    {
                        "type": "hostname",
                        "hostname": value,
                    }
                )

        if not exposures:
            return []

        severity = Severity.CRITICAL
        if not any(exp.get("type") == "external_ip" for exp in exposures):
            severity = self.severity

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        summary_parts = []
        for exposure in exposures:
            if exposure["type"] == "external_ip":
                summary_parts.append(
                    f"node has public external IP {exposure['address']}"
                )
            elif exposure["type"] == "hostname":
                summary_parts.append(
                    f"node has externally reachable hostname {exposure['hostname']}"
                )

        evidence = {
            "namespace": normalized.get("namespace"),
            "provider_id": normalized.get("providerID"),
            "unschedulable": normalized.get("unschedulable"),
            "exposures": exposures,
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "Kubernetes node "
                f"{resource.name or resource.external_id} exposes public endpoints"
            ),
            summary="; ".join(summary_parts),
            evidence=evidence,
            severity=severity,
        )

        return [finding]
