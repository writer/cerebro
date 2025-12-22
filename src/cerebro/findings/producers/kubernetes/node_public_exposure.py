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
from cerebro.findings.producers.base import BaseFindingProducer, ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import (
    ProducerRunContext,
    build_network_exposure_evidence,
    downgrade_severity_for_namespace_policy,
    exposures_contain_public,
    get_namespace_network_posture,
    resolve_rule_id,
)


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
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        run_context = ProducerRunContext.ensure(context)
        addresses = normalized.get("addresses") or []

        exposures: list[dict[str, Any]] = []

        for address in addresses:
            addr_type = (address.get("type") or "").upper()
            value = address.get("address")

            if addr_type == "EXTERNALIP" and _is_public_ip(value):
                exposures.append(
                    {
                        "type": "external_ip",
                        "ip": value,
                        "public": True,
                    }
                )
            elif addr_type == "HOSTNAME" and value:
                exposures.append(
                    {
                        "type": "hostname",
                        "metadata": {"hostname": value},
                    }
                )

        if not exposures:
            return []

        namespace = normalized.get("namespace")
        namespace_posture = get_namespace_network_posture(run_context, namespace)

        severity = (
            Severity.CRITICAL if exposures_contain_public(exposures) else self.severity
        )

        severity = downgrade_severity_for_namespace_policy(
            severity,
            namespace_posture=namespace_posture,
            when=Severity.CRITICAL,
            downgrade_to=self.severity,
            require_ingress_default_deny=True,
            require_egress_default_deny=True,
        )

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=run_context)

        summary_parts = []
        for exposure in exposures:
            if exposure["type"] == "external_ip":
                summary_parts.append(
                    f"node has public external IP {exposure.get('ip')}"
                )
            elif exposure["type"] == "hostname":
                summary_parts.append(
                    f"node has externally reachable hostname "
                    f"{exposure.get('metadata', {}).get('hostname')}"
                )

        evidence = build_network_exposure_evidence(
            namespace=normalized.get("namespace"),
            exposures=exposures,
            namespace_network_posture=namespace_posture,
            extra={
                "provider_id": normalized.get("providerID"),
                "unschedulable": normalized.get("unschedulable"),
            },
        )

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
