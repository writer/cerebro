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


def _security_group_rule_allows_public(
    rule: dict[str, Any], target_port: int | None
) -> bool:
    ipv4_cidrs = rule.get("ipv4Cidr") or []
    ipv6_cidrs = rule.get("ipv6Cidr") or []
    has_public_cidr = any(cidr == "0.0.0.0/0" for cidr in ipv4_cidrs) or any(
        cidr == "::/0" for cidr in ipv6_cidrs
    )
    if not has_public_cidr:
        return False

    protocol = rule.get("ipProtocol")
    from_port = rule.get("fromPort")
    to_port = rule.get("toPort")

    if protocol in {None, "-1"}:
        return True

    protocol = str(protocol).lower()
    if protocol not in {"tcp", "udp", "all"}:
        return False

    if target_port is None:
        return True

    if from_port is None and to_port is None:
        return True

    if from_port is None:
        from_port = to_port
    if to_port is None:
        to_port = from_port

    if from_port is None or to_port is None:
        return True

    return int(from_port) <= target_port <= int(to_port)


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
                    target_port = target_group.get("port")
                    for target in target_group.get("targets") or []:
                        instance_details = target.get("instance") or {}
                        exposure_sources: list[str] = []

                        public_ip = instance_details.get("publicIpAddress")
                        interface_ips = (
                            instance_details.get("networkInterfacePublicIps") or []
                        )
                        has_public_interface = (
                            instance_details.get("hasPublicInterface")
                            or _is_public_ip(public_ip)
                            or any(_is_public_ip(ip) for ip in interface_ips)
                        )

                        if has_public_interface:
                            exposure_sources.append("public_interface")

                        security_group_findings: list[dict[str, Any]] = []
                        for security_group in (
                            instance_details.get("securityGroups") or []
                        ):
                            group_id = security_group.get("groupId")
                            for rule in security_group.get("ingressRules") or []:
                                allows_public = _security_group_rule_allows_public(
                                    rule,
                                    target_port,
                                )
                                if allows_public:
                                    security_group_findings.append(
                                        {
                                            "groupId": group_id,
                                            "ipProtocol": rule.get("ipProtocol"),
                                            "fromPort": rule.get("fromPort"),
                                            "toPort": rule.get("toPort"),
                                            "ipv4Cidr": rule.get("ipv4Cidr"),
                                            "ipv6Cidr": rule.get("ipv6Cidr"),
                                        }
                                    )

                        if security_group_findings:
                            exposure_sources.append("security_group")

                        if not exposure_sources:
                            continue

                        public_instances.append(
                            {
                                "instanceId": target.get("id"),
                                "publicIpAddress": public_ip,
                                "interfacePublicIps": interface_ips,
                                "publicDnsName": instance_details.get("publicDnsName"),
                                "subnetId": instance_details.get("subnetId"),
                                "vpcId": instance_details.get("vpcId"),
                                "exposureSources": exposure_sources,
                                "securityGroupFindings": security_group_findings,
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
                for instance in exposure.get("publicInstances") or []:
                    identifier = instance.get("instanceId") or "unknown"
                    reasons: list[str] = []
                    if "public_interface" in instance.get("exposureSources", []):
                        reasons.append("public interface")
                    if instance.get("securityGroupFindings"):
                        group_ids = {
                            finding.get("groupId")
                            for finding in instance.get("securityGroupFindings") or []
                            if finding.get("groupId")
                        }
                        if group_ids:
                            reasons.append(
                                "open security group " + ", ".join(sorted(group_ids))
                            )
                        else:
                            reasons.append("open security group")
                    if reasons:
                        reason_text = " and ".join(reasons)
                    else:
                        reason_text = "public exposure"
                    summary_parts.append(
                        "listener "
                        f"{exposure['listenerArn']} forwards to instance {identifier} "
                        f"with {reason_text}"
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
