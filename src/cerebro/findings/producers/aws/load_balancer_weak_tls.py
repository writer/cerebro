"""Detect load balancer listeners using weak or legacy TLS policies."""

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
from cerebro.findings.producers.utils import ProducerRunContext, resolve_rule_id

from .base import BaseAWSProducer

SECURE_TLS_POLICIES = {
    "ELBSecurityPolicy-TLS13-1-2-2021-06",
    "ELBSecurityPolicy-TLS13-1-1-2021-06",
    "ELBSecurityPolicy-TLS13-Ext-1-2-2021-06",
    "ELBSecurityPolicy-FS-1-2-Res-2020-10",
    "ELBSecurityPolicy-FS-1-2-Res-2019-08",
    "ELBSecurityPolicy-FS-1-2-2019-08",
    "ELBSecurityPolicy-FS-1-2-Res-2018-06",
    "ELBSecurityPolicy-FS-1-2-2018-06",
}


def _is_secure_listener(listener: dict[str, Any]) -> bool:
    protocol = (listener.get("protocol") or "").upper()
    if protocol not in {"HTTPS", "TLS", "SSL"}:
        return True  # Non-TLS listeners handled by other producers

    policy = listener.get("sslPolicy")
    if not policy:
        return False

    if policy in SECURE_TLS_POLICIES:
        return True

    if policy.startswith("ELBSecurityPolicy-TLS13"):
        return True

    return False


@register_producer
class AwsLoadBalancerWeakTlsProducer(BaseAWSProducer):
    """Flag HTTPS/TLS listeners using deprecated security policies."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.elbv2.load_balancer"}

    @property
    def finding_name(self) -> str:
        return "AWS load balancer uses weak TLS policy"

    @property
    def rule_name(self) -> str:
        return "aws_load_balancer_weak_tls"

    @property
    def description(self) -> str:
        return "HTTPS listener relies on legacy TLS policy lacking modern ciphers"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        run_context = ProducerRunContext.ensure(context)
        listeners: list[dict[str, Any]] = normalized.get("listeners") or []

        insecure_listeners: list[dict[str, Any]] = []
        for listener in listeners:
            protocol = (listener.get("protocol") or "").upper()
            if protocol not in {"HTTPS", "TLS", "SSL"}:
                continue

            if _is_secure_listener(listener):
                continue

            insecure_listeners.append(
                {
                    "listenerArn": listener.get("listenerArn"),
                    "port": listener.get("port"),
                    "protocol": protocol,
                    "sslPolicy": listener.get("sslPolicy"),
                }
            )

        if not insecure_listeners:
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=run_context)

        evidence = {
            "loadBalancerArn": normalized.get("loadBalancerArn")
            or resource.external_id,
            "listeners": insecure_listeners,
        }

        summary_parts = []
        for listener in insecure_listeners:
            policy = listener.get("sslPolicy") or "none"
            summary_parts.append(
                f"listener on port {listener['port']} uses policy {policy}"
            )
        summary = "; ".join(summary_parts)

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "AWS load balancer "
                f"{evidence['loadBalancerArn']} uses weak TLS policy"
            ),
            summary=summary,
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
