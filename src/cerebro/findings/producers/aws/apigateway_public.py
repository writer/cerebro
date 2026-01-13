"""Producer for detecting publicly accessible API Gateway REST APIs."""

from __future__ import annotations

from collections.abc import Mapping
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


@register_producer
class APIGatewayPublicProducer(BaseAWSProducer):
    """Detect API Gateway REST APIs with public endpoints."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.apigateway.restapi", "aws.apigateway.api"}

    @property
    def finding_name(self) -> str:
        return "AWS: API Gateway Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "aws_apigateway_public"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "API Gateway REST API is publicly accessible from the internet."

    @property
    def remediation(self) -> str:
        return (
            "Configure the API as private with VPC endpoint access. "
            "Use resource policies to restrict access. "
            "Enable authorization on all methods."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7"],
            "cwe": ["CWE-284"],
            "cis_aws": ["2.6"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate API Gateway for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check endpoint type
        endpoint_config = data.get("endpoint_configuration", {}) or {}
        endpoint_types = endpoint_config.get("types", []) or []

        is_private = "PRIVATE" in endpoint_types
        is_public = not is_private or "EDGE" in endpoint_types or "REGIONAL" in endpoint_types

        if not is_public:
            return findings

        # Check for WAF
        waf_enabled = bool(data.get("web_acl_arn"))

        # Check for authorization
        has_authorizer = bool(data.get("authorizers"))

        risk_factors: list[str] = ["public_endpoint"]
        if not waf_enabled:
            risk_factors.append("no_waf")
        if not has_authorizer:
            risk_factors.append("no_authorizer")

        evidence = {
            "api_id": resource.external_id,
            "api_name": resource.name,
            "endpoint_types": endpoint_types,
            "is_private": is_private,
            "waf_enabled": waf_enabled,
            "web_acl_arn": data.get("web_acl_arn"),
            "has_authorizer": has_authorizer,
            "created_date": data.get("created_date"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"API Gateway {resource.name} is publicly accessible",
                summary=f"Endpoint: {', '.join(endpoint_types)}. WAF: {waf_enabled}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
