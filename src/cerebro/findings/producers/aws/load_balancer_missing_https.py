"""Detect internet-facing application load balancers lacking HTTPS listeners."""

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


def _is_secure_listener(listener: dict[str, Any]) -> bool:
    protocol = (listener.get("protocol") or "").upper()
    if protocol in {"HTTPS", "TLS", "SSL"}:
        return True
    return False


@register_producer
class AwsLoadBalancerMissingHttpsProducer(BaseAWSProducer):
    """Flag public application load balancers without secure listeners."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.elbv2.load_balancer"}

    @property
    def finding_name(self) -> str:
        return "AWS load balancer missing HTTPS listener"

    @property
    def rule_name(self) -> str:
        return "aws_load_balancer_missing_https"

    @property
    def description(self) -> str:
        return "Internet-facing application load balancer lacks HTTPS/TLS listener"

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
        scheme = (normalized.get("scheme") or "").lower()
        lb_type = (normalized.get("type") or "").lower()
        listeners: list[dict[str, Any]] = normalized.get("listeners") or []

        if scheme != "internet-facing" or lb_type != "application":
            return []

        has_secure_listener = any(
            _is_secure_listener(listener) for listener in listeners
        )

        if has_secure_listener:
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        evidence = {
            "loadBalancerArn": normalized.get("loadBalancerArn")
            or resource.external_id,
            "scheme": normalized.get("scheme"),
            "type": normalized.get("type"),
            "listeners": listeners,
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "AWS load balancer "
                f"{evidence['loadBalancerArn']} missing HTTPS listener"
            ),
            summary="no HTTPS/TLS listeners configured",
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
