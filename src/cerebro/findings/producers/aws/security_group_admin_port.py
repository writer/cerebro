"""Detect AWS security groups exposing administrative ports to the internet."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, cast

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import (
    ProducerRunContext,
    build_security_group_exposure,
    resolve_rule_id,
)

from .base import BaseAWSProducer

ADMIN_PORTS: dict[int, str] = {
    22: "SSH",
    3389: "RDP",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
}

WORLD_IPV4 = "0.0.0.0/0"
WORLD_IPV6 = "::/0"


def _port_in_range(port: int, rule: dict[str, Any]) -> bool:
    from_port_value = rule.get("fromPort")
    to_port_value = rule.get("toPort")
    protocol = str(rule.get("ipProtocol") or "").lower()

    if protocol in {"icmp", "icmpv6", "udp"}:
        # Administrative protocols of interest are TCP-based
        return False

    if from_port_value is None or to_port_value is None:
        # Protocol -1 exposes all ports
        return True

    try:
        from_port_int = int(from_port_value)
        to_port_int = int(to_port_value)
    except (TypeError, ValueError):
        return False

    return from_port_int <= port <= to_port_int


def _rule_exposes_world(rule: dict[str, Any]) -> list[str]:
    cidrs: list[str] = []
    for cidr in cast(Iterable[str], rule.get("ipv4Cidr") or []):
        if cidr == WORLD_IPV4:
            cidrs.append(cidr)
    for cidr in cast(Iterable[str], rule.get("ipv6Cidr") or []):
        if cidr == WORLD_IPV6:
            cidrs.append(cidr)
    return cidrs


@register_producer
class AwsSecurityGroupAdminPortProducer(BaseAWSProducer):
    """Flag security groups exposing admin ports to anonymous internet clients."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.ec2.security_group"}

    @property
    def finding_name(self) -> str:
        return "AWS security group exposes administrative ports"

    @property
    def rule_name(self) -> str:
        return "aws_security_group_admin_port_exposure"

    @property
    def description(self) -> str:
        return (
            "Security group allows 0.0.0.0/0 or ::/0 ingress to administrative "
            "protocol ports"
        )

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        run_context = ProducerRunContext.ensure(context)

        normalized = config.normalized_config or {}
        ingress_rules: list[dict[str, Any]] = normalized.get("ingressRules") or []

        exposed_rules: list[dict[str, Any]] = []

        for rule in ingress_rules:
            exposed_cidrs = _rule_exposes_world(rule)
            if not exposed_cidrs:
                continue

            for port, service in ADMIN_PORTS.items():
                if _port_in_range(port, rule):
                    exposed_rules.append(
                        {
                            "type": "admin_port_exposure",
                            "direction": "ingress",
                            "from_port": port,
                            "to_port": port,
                            "port": port,
                            "service": service,
                            "protocol": rule.get("ipProtocol"),
                            "cidr": exposed_cidrs[0],
                            "cidrs": exposed_cidrs,
                            "metadata": {
                                "cidrs": exposed_cidrs,
                                "service": service,
                            },
                        }
                    )

        if not exposed_rules:
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=run_context)

        evidence = build_security_group_exposure(
            group_id=normalized.get("groupId") or resource.external_id,
            group_name=normalized.get("groupName"),
            vpc_id=normalized.get("vpcId"),
            attached_resources=normalized.get("networkInterfaceIds"),
            public_rules=exposed_rules,
            total_rules=len(ingress_rules),
            metadata={
                "owner_id": normalized.get("ownerId"),
                "tags": normalized.get("tags"),
            },
        )

        summary_parts = []
        for exposure in exposed_rules:
            cidrs = ", ".join(exposure["cidrs"])
            summary_parts.append(
                f"{exposure['service']} on port {exposure['port']} open to {cidrs}"
            )
        summary = "; ".join(summary_parts)

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "AWS security group "
                f"{evidence['group_id']} exposes administrative ports"
            ),
            summary=summary,
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
