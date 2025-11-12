"""Tests for AWS load balancer missing HTTPS producer."""

from __future__ import annotations

from datetime import datetime

from cerebro.domain.entities import ConfigEntity, ResourceEntity, Severity
from cerebro.findings.producers.aws.load_balancer_missing_https import (
    AwsLoadBalancerMissingHttpsProducer,
)


def _make_resource(lb_arn: str, name: str | None = None) -> ResourceEntity:
    return ResourceEntity(
        external_id=lb_arn,
        resource_type="aws.elbv2.load_balancer",
        provider="aws",
        name=name,
    )


def test_public_application_lb_without_https() -> None:
    producer = AwsLoadBalancerMissingHttpsProducer()

    resource = _make_resource(
        "arn:aws:elasticloadbalancing:lb/app/no-https",
        "no-https",
    )
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "scheme": "internet-facing",
            "type": "application",
            "listeners": [
                {
                    "listenerArn": "arn:listener/http",
                    "port": 80,
                    "protocol": "HTTP",
                    "defaultActions": [],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    assert finding.summary == "no HTTPS/TLS listeners configured"


def test_application_lb_with_https_listener() -> None:
    producer = AwsLoadBalancerMissingHttpsProducer()

    resource = _make_resource(
        "arn:aws:elasticloadbalancing:lb/app/with-https",
        "with-https",
    )
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "scheme": "internet-facing",
            "type": "application",
            "listeners": [
                {
                    "listenerArn": "arn:listener/https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "defaultActions": [],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []


def test_internal_lb_not_flagged() -> None:
    producer = AwsLoadBalancerMissingHttpsProducer()

    resource = _make_resource(
        "arn:aws:elasticloadbalancing:lb/app/internal",
        "internal",
    )
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "scheme": "internal",
            "type": "application",
            "listeners": [
                {
                    "listenerArn": "arn:listener/http",
                    "port": 80,
                    "protocol": "HTTP",
                    "defaultActions": [],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []
