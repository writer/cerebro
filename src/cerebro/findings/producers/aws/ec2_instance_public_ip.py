"""Producer for detecting EC2 instances with public IP addresses."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import (
    coerce_mapping,
    coerce_str_sequence,
    resolve_rule_id,
)

from .base import BaseAWSProducer


@register_producer
class EC2InstancePublicIPProducer(BaseAWSProducer):
    """Detects EC2 instances with public IP addresses."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.ec2.instance"}

    @property
    def finding_name(self) -> str:
        return "AWS: EC2 Instance Has Public IP"

    @property
    def rule_name(self) -> str:
        return "aws_ec2_instance_public_ip"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "EC2 instance has a public IP address directly assigned"

    @property
    def remediation(self) -> str:
        return (
            "Place EC2 instances in private subnets and use a NAT gateway or "
            "load balancer for outbound internet access."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "cis": ["4.1"],
            "nist_800_53": ["AC-4", "SC-7"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate EC2 instance for public IP assignment."""
        findings: list[FindingEntity] = []

        normalized = config.normalized_config or {}
        public_ip = normalized.get("publicIp")
        instance_state = normalized.get("state")

        if public_ip and instance_state == "running":
            rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

            security_groups = coerce_str_sequence(normalized.get("securityGroups"))
            open_to_internet = self._check_security_groups_open(
                security_groups,
                context,
            )

            risk_factors: list[str] = []
            if open_to_internet:
                risk_factors.append("security_groups_allow_internet_access")

            instance_type = normalized.get("instanceType")
            if instance_type and instance_type.startswith(("t2.", "t3.", "t4g.")):
                risk_factors.append("burstable_instance_type")

            evidence = {
                "instance_id": resource.external_id,
                "instance_name": resource.name,
                "instance_type": instance_type,
                "state": instance_state,
                "public_ip": public_ip,
                "private_ip": normalized.get("privateIp"),
                "vpc_id": normalized.get("vpcId"),
                "subnet_id": normalized.get("subnetId"),
                "security_groups": security_groups,
                "open_to_internet": open_to_internet,
                "risk_factors": risk_factors,
                "tags": normalized.get("tags", {}),
                "image_id": normalized.get("imageId"),
                "launch_time": normalized.get("launchTime"),
            }

            severity = Severity.HIGH if open_to_internet else self.severity

            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=(
                    "EC2 instance "
                    f"{resource.name or resource.external_id} has public IP"
                ),
                summary=(
                    "EC2 instance "
                    f"{resource.name or resource.external_id} has public IP {public_ip}"
                    f"{' and open security groups' if open_to_internet else ''}"
                ),
                evidence=evidence,
                severity=severity,
            )
            findings.append(finding)

        return findings

    def _check_security_groups_open(
        self,
        security_groups: Sequence[str],
        context: ProducerContext | None,
    ) -> bool:
        """Check if security groups allow open internet access."""
        if not security_groups or not context:
            return False

        rules_by_group = _normalize_security_group_rules(
            context.get("security_group_rules")
        )
        if not rules_by_group:
            return False

        for sg_id in security_groups:
            for rule in rules_by_group.get(sg_id, []):
                cidr = rule.get("cidr")
                if cidr not in {"0.0.0.0/0", "::/0"}:
                    continue

                from_port = _safe_int(rule.get("from_port"))
                to_port = _safe_int(rule.get("to_port"))

                if _port_in_range(22, from_port, to_port):
                    return True
                if _port_in_range(80, from_port, to_port):
                    return True
                if _port_in_range(443, from_port, to_port):
                    return True

        return False


def _safe_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _port_in_range(port: int, start: int | None, end: int | None) -> bool:
    if start is None or end is None:
        return False
    return start <= port <= end


def _normalize_security_group_rules(
    value: Any,
) -> dict[str, list[Mapping[str, Any]]]:
    rules_by_group: dict[str, list[Mapping[str, Any]]] = {}

    if isinstance(value, Mapping):
        for sg_id, rules in value.items():
            if not isinstance(sg_id, str) or not sg_id:
                continue
            collected = _ensure_mapping_sequence(rules)
            if collected:
                rules_by_group.setdefault(sg_id, []).extend(collected)
        return rules_by_group

    for entry in _ensure_mapping_sequence(value):
        sg_id = entry.get("security_group_id")
        if isinstance(sg_id, str) and sg_id:
            rules_by_group.setdefault(sg_id, []).append(entry)

    return rules_by_group


def _ensure_mapping_sequence(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        collected: list[Mapping[str, Any]] = []
        for item in value:
            mapping = coerce_mapping(item)
            if mapping is not None:
                collected.append(mapping)
        return collected

    mapping = coerce_mapping(value)
    return [mapping] if mapping is not None else []
