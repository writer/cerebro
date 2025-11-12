"""Detect load balancer certificates nearing expiration."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.registry import register_producer

from .base import BaseAWSProducer

EXPIRY_WARNING = timedelta(days=30)
EXPIRY_CRITICAL = timedelta(days=7)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z")
        except ValueError:
            return None


@register_producer
class AwsLoadBalancerCertificateExpiryProducer(BaseAWSProducer):
    """Flag certificates attached to load balancers that expire soon."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.elbv2.load_balancer"}

    @property
    def finding_name(self) -> str:
        return "AWS load balancer certificate nearing expiration"

    @property
    def rule_name(self) -> str:
        return "aws_load_balancer_certificate_expiry"

    @property
    def description(self) -> str:
        return "HTTPS listener certificates expire within 30 days"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: dict[str, Any] | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        listeners: list[dict[str, Any]] = normalized.get("listeners") or []

        now = datetime.now(timezone.utc)  # noqa: UP017
        exposures: list[dict[str, Any]] = []
        highest_severity = self.severity

        for listener in listeners:
            protocol = (listener.get("protocol") or "").upper()
            if protocol not in {"HTTPS", "TLS", "SSL"}:
                continue

            for certificate in listener.get("certificates") or []:
                expiry = _parse_timestamp(certificate.get("notAfter"))
                if not expiry:
                    continue

                time_remaining = expiry - now
                if time_remaining <= timedelta(0):
                    severity = Severity.CRITICAL
                elif time_remaining <= EXPIRY_CRITICAL:
                    severity = Severity.CRITICAL
                elif time_remaining <= EXPIRY_WARNING:
                    severity = Severity.HIGH
                else:
                    continue

                if severity == Severity.CRITICAL:
                    highest_severity = Severity.CRITICAL
                elif (
                    severity == Severity.HIGH
                    and highest_severity != Severity.CRITICAL
                ):
                    highest_severity = Severity.HIGH

                exposures.append(
                    {
                        "listenerArn": listener.get("listenerArn"),
                        "port": listener.get("port"),
                        "certificateArn": certificate.get("certificateArn"),
                        "notAfter": certificate.get("notAfter"),
                        "daysUntilExpiry": time_remaining.total_seconds() / 86400,
                        "severity": severity.name,
                    }
                )

        if not exposures:
            return []

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        evidence = {
            "loadBalancerArn": normalized.get("loadBalancerArn")
            or resource.external_id,
            "exposures": exposures,
        }

        summary = "; ".join(
            f"certificate {exp['certificateArn']} expires on {exp['notAfter']}"
            for exp in exposures
        )

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "AWS load balancer "
                f"{evidence['loadBalancerArn']} certificate expiration warning"
            ),
            summary=summary,
            evidence=evidence,
            severity=highest_severity,
        )

        return [finding]
