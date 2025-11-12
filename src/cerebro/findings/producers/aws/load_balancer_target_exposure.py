"""Detect internet-facing load balancers with public target IP exposure."""

from __future__ import annotations

import ipaddress
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.registry import register_producer

from .base import BaseAWSProducer


def _is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        not ip_obj.is_private
        and not ip_obj.is_loopback
        and not ip_obj.is_multicast
        and not ip_obj.is_unspecified
    )


@register_producer
class AwsLoadBalancerTargetExposureProducer(BaseAWSProducer):
    """Flag load balancers routing traffic directly to public IP targets."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.elbv2.load_balancer"}

    @property
    def finding_name(self) -> str:
        return "AWS load balancer forwards to public targets"

    @property
    def rule_name(self) -> str:
        return "aws_load_balancer_public_target"

    @property
    def description(self) -> str:
        return "Internet-facing load balancer routes to public IP targets"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: dict[str, Any] | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        scheme = (normalized.get("scheme") or "").lower()
        if scheme != "internet-facing":
            return []

        target_groups: list[dict[str, Any]] = normalized.get("targetGroups") or []
        listeners: list[dict[str, Any]] = normalized.get("listeners") or []

        target_group_by_arn: dict[str, dict[str, Any]] = {}
        for target_group in target_groups:
            arn = target_group.get("targetGroupArn")
            if arn:
                target_group_by_arn[arn] = target_group

        affected: list[dict[str, Any]] = []

        for listener in listeners:
            protocol = (listener.get("protocol") or "").upper()
            if protocol not in {"HTTP", "HTTPS", "TLS"}:
                continue

            for action in listener.get("defaultActions") or []:
                tg_arn = action.get("targetGroupArn")
                if not tg_arn or tg_arn not in target_group_by_arn:
                    continue

                target_group = target_group_by_arn[tg_arn]
                target_type = (target_group.get("targetType") or "").lower()

                if target_type == "ip":
                    public_targets = [
                        target
                        for target in target_group.get("targets") or []
                        if _is_public_ip(target.get("id"))
                    ]

                    if not public_targets:
                        continue

                    affected.append(
                        {
                            "listenerArn": listener.get("listenerArn"),
                            "port": listener.get("port"),
                            "targetGroupArn": tg_arn,
                            "targetType": "ip",
                            "publicTargets": [
                                target.get("id") for target in public_targets
                            ],
                        }
                    )

                elif target_type == "instance":
                    public_instances = []
                    for target in target_group.get("targets") or []:
                        instance_details = target.get("instance") or {}
                        has_public_interface = instance_details.get(
                            "hasPublicInterface"
                        )
                        public_ip = instance_details.get("publicIpAddress")
                        interface_ips = (
                            instance_details.get("networkInterfacePublicIps") or []
                        )

                        if not (
                            has_public_interface
                            or _is_public_ip(public_ip)
                            or any(_is_public_ip(ip) for ip in interface_ips)
                        ):
                            continue

                        public_instances.append(
                            {
                                "instanceId": target.get("id"),
                                "publicIpAddress": public_ip,
                                "interfacePublicIps": interface_ips,
                                "publicDnsName": instance_details.get("publicDnsName"),
                                "subnetId": instance_details.get("subnetId"),
                                "vpcId": instance_details.get("vpcId"),
                            }
                        )

                    if not public_instances:
                        continue

                    affected.append(
                        {
                            "listenerArn": listener.get("listenerArn"),
                            "port": listener.get("port"),
                            "targetGroupArn": tg_arn,
                            "targetType": "instance",
                            "publicInstances": public_instances,
                        }
                    )

        if not affected:
            return []

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        evidence = {
            "loadBalancerArn": normalized.get("loadBalancerArn")
            or resource.external_id,
            "exposures": affected,
        }

        summary_parts = []
        for exposure in affected:
            if exposure.get("targetType") == "instance":
                instance_ids = ", ".join(
                    instance.get("instanceId") or ""
                    for instance in exposure.get("publicInstances") or []
                    if instance.get("instanceId")
                )
                summary_parts.append(
                    "listener "
                    f"{exposure['listenerArn']} forwards to public instances "
                    f"{instance_ids}"
                )
            else:
                public_targets = ", ".join(exposure.get("publicTargets", []))
                summary_parts.append(
                    "listener "
                    f"{exposure['listenerArn']} forwards to public targets "
                    f"{public_targets}"
                )
        summary = "; ".join(summary_parts)

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "AWS load balancer "
                f"{evidence['loadBalancerArn']} routes to public targets"
            ),
            summary=summary,
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
