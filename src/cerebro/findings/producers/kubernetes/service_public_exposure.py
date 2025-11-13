"""Detect Kubernetes services exposing workloads publicly."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any, cast

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
    exposures_contain_type,
    get_namespace_network_posture,
    resolve_rule_id,
)

INTERNAL_ANNOTATION_KEYS = {
    "service.beta.kubernetes.io/aws-load-balancer-internal",
    "service.beta.kubernetes.io/azure-load-balancer-internal",
    "cloud.google.com/load-balancer-type",
    "service.kubernetes.io/load-balancer-internal",
    "service.beta.kubernetes.io/openstack-internal-load-balancer",
}


def _is_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "on"}
    return False


def _is_internal_load_balancer(annotations: dict[str, Any]) -> bool:
    for key, value in annotations.items():
        if key not in INTERNAL_ANNOTATION_KEYS:
            continue
        if key == "cloud.google.com/load-balancer-type":
            if str(value).strip().lower() == "internal":
                return True
        elif _is_truthy(value):
            return True
    return False


def _is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False

    return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)


@register_producer
class K8sServicePublicExposureProducer(BaseFindingProducer):
    """Detect services exposing workloads publicly via load balancers or node ports."""

    @property
    def desired_sources(self) -> set[str]:
        return {"kubernetes"}

    @property
    def resource_types(self) -> set[str]:
        return {"k8s.service"}

    @property
    def finding_name(self) -> str:
        return "Kubernetes service exposes workload publicly"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def rule_name(self) -> str:
        return "k8s_service_public_exposure"

    @property
    def description(self) -> str:
        return "Service publishes external endpoints via load balancer or node port"

    @property
    def remediation(self) -> str:
        return (
            "Restrict service exposure to internal load balancers, remove node ports, "
            "or enforce network policies to limit external access."
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        service_type = (normalized.get("type") or "").upper()
        annotations = normalized.get("annotations") or {}
        namespace = normalized.get("namespace")

        run_context = ProducerRunContext.ensure(context)
        namespace_posture = get_namespace_network_posture(run_context, namespace)

        exposures: list[dict[str, Any]] = []

        if service_type == "LOADBALANCER":
            exposures.extend(self._evaluate_load_balancer(normalized, annotations))
        elif service_type == "NODEPORT":
            for port in normalized.get("ports") or []:
                exposures.append(
                    {
                        "type": "node_port",
                        "port": port.get("nodePort"),
                        "service_port": port.get("port"),
                    }
                )
        elif normalized.get("externalIPs"):
            external_ips = cast(Iterable[str], normalized.get("externalIPs"))
            for ip in external_ips:
                exposures.append(
                    {
                        "type": "external_ip",
                        "ip": ip,
                        "public": _is_public_ip(ip),
                    }
                )

        if not exposures:
            return []

        public_exposure = exposures_contain_public(exposures)
        node_port_exposure = exposures_contain_type(exposures, "node_port")

        if public_exposure:
            severity = Severity.CRITICAL
        elif node_port_exposure:
            severity = self.severity
        else:
            severity = Severity.MEDIUM

        severity = downgrade_severity_for_namespace_policy(
            severity,
            namespace_posture=namespace_posture,
            when=Severity.CRITICAL,
            downgrade_to=self.severity,
            require_ingress_default_deny=True,
            require_egress_default_deny=True,
        )

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=run_context)

        summary_parts: list[str] = []
        for exposure in exposures:
            exposure_type = exposure.get("type")
            if exposure_type == "load_balancer_ip":
                summary_parts.append(
                    f"load balancer IP {exposure.get('ip')} is publicly reachable"
                )
            elif exposure_type == "load_balancer_hostname":
                summary_parts.append(
                    f"load balancer hostname {exposure.get('hostname')} exposed"
                )
            elif exposure_type == "node_port":
                summary_parts.append(
                    f"node port {exposure.get('port')} forwards service port "
                    f"{exposure.get('service_port')}"
                )
            elif exposure_type == "external_ip":
                summary_parts.append(
                    f"external IP {exposure.get('ip')} assigned to service"
                )

        evidence = build_network_exposure_evidence(
            namespace=namespace,
            exposures=exposures,
            annotations=annotations,
            namespace_network_posture=namespace_posture,
            service_type=service_type,
        )

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "Kubernetes service "
                f"{resource.name or resource.external_id} exposes workload publicly"
            ),
            summary="; ".join(summary_parts),
            evidence=evidence,
            severity=severity,
        )

        return [finding]

    def _evaluate_load_balancer(
        self,
        normalized: dict[str, Any],
        annotations: dict[str, Any],
    ) -> list[dict[str, Any]]:
        if _is_internal_load_balancer(annotations):
            # Assume internal load balancers are controlled, but still surface external
            # IPs that are globally routable.
            internal_only = True
        else:
            internal_only = False

        exposures: list[dict[str, Any]] = []

        for entry in normalized.get("loadBalancer") or []:
            ip_value = entry.get("ip")
            hostname = entry.get("hostname")

            if ip_value:
                is_public = _is_public_ip(ip_value)
                if internal_only and not is_public:
                    continue
                exposures.append(
                    {
                        "type": "load_balancer_ip",
                        "ip": ip_value,
                        "public": is_public,
                    }
                )
            if hostname:
                exposures.append(
                    {
                        "type": "load_balancer_hostname",
                        "hostname": hostname,
                        "public": not internal_only,
                    }
                )

        external_ips = cast(Iterable[str], normalized.get("externalIPs") or [])
        for ip_value in external_ips:
            is_public = _is_public_ip(ip_value)
            if internal_only and not is_public:
                continue
            exposures.append(
                {
                    "type": "external_ip",
                    "ip": ip_value,
                    "public": is_public,
                }
            )

        return exposures
