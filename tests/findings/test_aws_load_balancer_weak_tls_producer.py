"""Tests for AWS load balancer weak TLS producer."""

from __future__ import annotations

from datetime import datetime

from cerebro.domain.entities import ConfigEntity, ResourceEntity, Severity
from cerebro.findings.producers.aws.load_balancer_weak_tls import (
    AwsLoadBalancerWeakTlsProducer,
)


def _make_resource(lb_arn: str, name: str | None = None) -> ResourceEntity:
    return ResourceEntity(
        external_id=lb_arn,
        resource_type="aws.elbv2.load_balancer",
        provider="aws",
        name=name,
    )


def test_listener_without_policy_flagged() -> None:
    producer = AwsLoadBalancerWeakTlsProducer()

    resource = _make_resource("arn:aws:elasticloadbalancing:lb/app/sample", "sample")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "listeners": [
                {
                    "listenerArn": "arn:listener/https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "sslPolicy": None,
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["listeners"][0]["sslPolicy"] is None


def test_listener_with_legacy_policy_flagged() -> None:
    producer = AwsLoadBalancerWeakTlsProducer()

    resource = _make_resource("arn:aws:elasticloadbalancing:lb/app/legacy", "legacy")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "listeners": [
                {
                    "listenerArn": "arn:listener/https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "sslPolicy": "ELBSecurityPolicy-2015-05",
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    exposure = findings[0].evidence["listeners"][0]
    assert exposure["sslPolicy"] == "ELBSecurityPolicy-2015-05"


def test_listener_with_modern_policy_not_flagged() -> None:
    producer = AwsLoadBalancerWeakTlsProducer()

    resource = _make_resource("arn:aws:elasticloadbalancing:lb/app/modern", "modern")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "listeners": [
                {
                    "listenerArn": "arn:listener/https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "sslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []


def test_non_tls_listener_not_flagged() -> None:
    producer = AwsLoadBalancerWeakTlsProducer()

    resource = _make_resource("arn:aws:elasticloadbalancing:lb/app/http", "http")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "listeners": [
                {
                    "listenerArn": "arn:listener/http",
                    "port": 80,
                    "protocol": "HTTP",
                    "sslPolicy": None,
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []
