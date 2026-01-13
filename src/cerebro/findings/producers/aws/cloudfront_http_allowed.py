"""Producer for detecting CloudFront distributions allowing HTTP."""

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
class CloudFrontHTTPAllowedProducer(BaseAWSProducer):
    """Detect CloudFront distributions allowing HTTP (not HTTPS-only)."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.cloudfront.distribution"}

    @property
    def finding_name(self) -> str:
        return "AWS: CloudFront Allows HTTP"

    @property
    def rule_name(self) -> str:
        return "aws_cloudfront_http_allowed"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "CloudFront distribution allows viewers to use HTTP instead of HTTPS."

    @property
    def remediation(self) -> str:
        return (
            "Configure viewer protocol policy to redirect-to-https or https-only. "
            "Ensure origin protocol policy also uses HTTPS."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["SC-8", "SC-23"],
            "cwe": ["CWE-319"],
            "cis_aws": ["2.5"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate CloudFront distribution for HTTPS enforcement."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check default cache behavior
        default_cache = data.get("default_cache_behavior", {}) or {}
        viewer_protocol = default_cache.get("ViewerProtocolPolicy", "").lower()

        secure_protocols = {"redirect-to-https", "https-only"}
        if viewer_protocol in secure_protocols:
            return findings

        # Check WAF
        waf_id = data.get("web_acl_id")
        logging_enabled = bool(data.get("logging", {}).get("Enabled"))

        risk_factors: list[str] = ["http_allowed"]
        if not waf_id:
            risk_factors.append("no_waf")
        if not logging_enabled:
            risk_factors.append("logging_disabled")

        evidence = {
            "distribution_id": resource.external_id,
            "domain_name": data.get("domain_name"),
            "viewer_protocol_policy": viewer_protocol or "allow-all",
            "waf_enabled": bool(waf_id),
            "logging_enabled": logging_enabled,
            "enabled": data.get("enabled"),
            "price_class": data.get("price_class"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"CloudFront distribution {resource.external_id} allows HTTP",
                summary=f"Viewer protocol: {viewer_protocol or 'allow-all'}. WAF: {bool(waf_id)}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
