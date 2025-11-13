"""Detect public load balancers serving plaintext HTTP."""

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


def _is_https_redirect(action: dict[str, Any]) -> bool:
    if action.get("type", "").lower() != "redirect":
        return False

    redirect_config = action.get("redirectConfig") or {}
    protocol = (redirect_config.get("Protocol") or "").upper()
    status_code = redirect_config.get("StatusCode")
    return protocol == "HTTPS" and status_code in {"HTTP_301", "HTTP_302"}


@register_producer
class AwsLoadBalancerPublicHttpProducer(BaseAWSProducer):
    """Flag internet-facing load balancers exposing HTTP without redirect."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.elbv2.load_balancer"}

    @property
    def finding_name(self) -> str:
        return "AWS load balancer exposes plaintext HTTP"

    @property
    def rule_name(self) -> str:
        return "aws_load_balancer_public_http"

    @property
    def description(self) -> str:
        return "Internet-facing load balancer listens on HTTP without HTTPS redirect"

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
        listeners: list[dict[str, Any]] = normalized.get("listeners") or []

        if scheme != "internet-facing":
            return []

        insecure_listeners: list[dict[str, Any]] = []

        for listener in listeners:
            protocol = (listener.get("protocol") or "").upper()
            port = listener.get("port")
            if protocol != "HTTP":
                continue

            default_actions = listener.get("defaultActions") or []
            if any(_is_https_redirect(action) for action in default_actions):
                continue

            insecure_listeners.append(
                {
                    "listenerArn": listener.get("listenerArn"),
                    "port": port,
                    "protocol": protocol,
                    "defaultActions": default_actions,
                }
            )

        if not insecure_listeners:
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=run_context)

        evidence = {
            "loadBalancerArn": normalized.get("loadBalancerArn")
            or resource.external_id,
            "scheme": normalized.get("scheme"),
            "listeners": insecure_listeners,
        }

        summary = "; ".join(
            f"listener on port {listener['port']} serves HTTP without redirect"
            for listener in insecure_listeners
        )

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "AWS load balancer "
                f"{evidence['loadBalancerArn']} exposes plaintext HTTP"
            ),
            summary=summary,
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
