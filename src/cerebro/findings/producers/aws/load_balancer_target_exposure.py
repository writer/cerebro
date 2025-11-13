"""Detect internet-facing load balancers with public target IP exposure."""

from __future__ import annotations

import ipaddress
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
    analyze_instance_network_exposure,
    exposures_contain_public,
    resolve_rule_id,
)

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
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        run_context = ProducerRunContext.ensure(context)
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
                    public_instances: list[dict[str, Any]] = []
                    target_port = target_group.get("port")
                    for target in target_group.get("targets") or []:
                        instance_exposure = analyze_instance_network_exposure(
                            target.get("id"),
                            target.get("instance"),
                            target_port,
                        )
                        if instance_exposure:
                            public_instances.append(instance_exposure)

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

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=run_context)

        evidence = {
            "loadBalancerArn": normalized.get("loadBalancerArn")
            or resource.external_id,
            "exposures": affected,
        }

        severity = (
            Severity.CRITICAL if exposures_contain_public(affected) else self.severity
        )

        summary_parts: list[str] = []
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
                exposure_targets = cast(
                    list[str], exposure.get("publicTargets") or []
                )
                joined_targets = ", ".join(exposure_targets)
                summary_parts.append(
                    "listener "
                    f"{exposure['listenerArn']} forwards to public targets "
                    f"{joined_targets}"
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
            severity=severity,
        )

        return [finding]
