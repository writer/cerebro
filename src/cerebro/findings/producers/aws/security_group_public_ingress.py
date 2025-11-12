"""Detect AWS security groups with wide-open ingress."""

from __future__ import annotations

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

from .base import BaseAWSProducer

WORLD_IPV4 = "0.0.0.0/0"
WORLD_IPV6 = "::/0"


def _rule_exposes_world(rule: dict[str, Any]) -> list[str]:
    cidrs: list[str] = []
    for cidr in rule.get("ipv4Cidr", []) or []:
        if cidr == WORLD_IPV4:
            cidrs.append(cidr)
    for cidr in rule.get("ipv6Cidr", []) or []:
        if cidr == WORLD_IPV6:
            cidrs.append(cidr)
    return cidrs


@register_producer
class AwsSecurityGroupPublicIngressProducer(BaseAWSProducer):
    """Flag security groups allowing unrestricted ingress."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.ec2.security_group"}

    @property
    def finding_name(self) -> str:
        return "AWS security group allows unrestricted ingress"

    @property
    def rule_name(self) -> str:
        return "aws_security_group_public_ingress"

    @property
    def description(self) -> str:
        return "Security group permits 0.0.0.0/0 or ::/0 inbound access"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        ingress_rules: list[dict[str, Any]] = normalized.get("ingressRules") or []

        exposures: list[dict[str, Any]] = []

        for rule in ingress_rules:
            cidrs = _rule_exposes_world(rule)
            if not cidrs:
                continue

            from_port = rule.get("fromPort")
            to_port = rule.get("toPort")
            protocol = rule.get("ipProtocol")

            if from_port is None and to_port is None:
                exposures.append(
                    {
                        "type": "all_ports",
                        "protocol": protocol,
                        "cidrs": cidrs,
                    }
                )
            else:
                exposures.append(
                    {
                        "type": "port_range",
                        "protocol": protocol,
                        "fromPort": from_port,
                        "toPort": to_port,
                        "cidrs": cidrs,
                    }
                )

        if not exposures:
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        severity = self._determine_severity(exposures)

        evidence = {
            "groupId": normalized.get("groupId") or resource.external_id,
            "groupName": normalized.get("groupName"),
            "vpcId": normalized.get("vpcId"),
            "exposures": exposures,
        }

        summary_parts: list[str] = []
        for exposure in exposures:
            cidr_text = ", ".join(exposure["cidrs"])
            if exposure["type"] == "all_ports":
                summary_parts.append(f"all ports open to {cidr_text}")
            else:
                from_port = exposure.get("fromPort")
                to_port = exposure.get("toPort")
                if from_port == to_port:
                    port_label = f"port {from_port}"
                else:
                    port_label = f"ports {from_port}-{to_port}"
                summary_parts.append(f"{port_label} open to {cidr_text}")

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                f"AWS security group {evidence['groupId']} allows unrestricted ingress"
            ),
            summary="; ".join(summary_parts),
            evidence=evidence,
            severity=severity,
        )

        return [finding]

    def _determine_severity(self, exposures: list[dict[str, Any]]) -> Severity:
        if any(exposure["type"] == "all_ports" for exposure in exposures):
            return Severity.CRITICAL
        return self.severity
