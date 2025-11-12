"""Tests for load balancer certificate expiry producer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cerebro.domain.entities import ConfigEntity, ResourceEntity, Severity
from cerebro.findings.producers.aws.load_balancer_certificate_expiry import (
    AwsLoadBalancerCertificateExpiryProducer,
)


def _make_resource(lb_arn: str) -> ResourceEntity:
    return ResourceEntity(
        external_id=lb_arn,
        resource_type="aws.elbv2.load_balancer",
        provider="aws",
        name="lb",
    )


def _make_cert(days_until_expiry: int) -> dict[str, str | None]:
    expiry = datetime.now(timezone.utc) + timedelta(days=days_until_expiry)  # noqa: UP017
    return {
        "certificateArn": "arn:aws:acm:cert/example",
        "isDefault": True,
        "notAfter": expiry.isoformat(),
    }


def test_certificate_expiring_within_week() -> None:
    producer = AwsLoadBalancerCertificateExpiryProducer()
    resource = _make_resource("arn:aws:elasticloadbalancing:lb/app/soon")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.now(timezone.utc),  # noqa: UP017
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "listeners": [
                {
                    "listenerArn": "arn:listener/https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "certificates": [_make_cert(3)],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_certificate_expiring_within_month() -> None:
    producer = AwsLoadBalancerCertificateExpiryProducer()
    resource = _make_resource("arn:aws:elasticloadbalancing:lb/app/month")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.now(timezone.utc),  # noqa: UP017
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "listeners": [
                {
                    "listenerArn": "arn:listener/https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "certificates": [_make_cert(20)],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_certificate_far_future_not_flagged() -> None:
    producer = AwsLoadBalancerCertificateExpiryProducer()
    resource = _make_resource("arn:aws:elasticloadbalancing:lb/app/future")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.now(timezone.utc),  # noqa: UP017
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "listeners": [
                {
                    "listenerArn": "arn:listener/https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "certificates": [_make_cert(90)],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []
