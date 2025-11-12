"""Tests for AWS load balancer public HTTP exposure producer."""

from __future__ import annotations

from datetime import datetime

from cerebro.domain.entities import ConfigEntity, ResourceEntity, Severity
from cerebro.findings.producers.aws.load_balancer_public_http import (
    AwsLoadBalancerPublicHttpProducer,
)


def _make_resource(lb_arn: str, name: str | None = None) -> ResourceEntity:
    return ResourceEntity(
        external_id=lb_arn,
        resource_type="aws.elbv2.load_balancer",
        provider="aws",
        name=name,
    )


def test_internet_facing_http_without_redirect() -> None:
    producer = AwsLoadBalancerPublicHttpProducer()

    resource = _make_resource("arn:aws:elasticloadbalancing:lb/app/sample", "sample")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "scheme": "internet-facing",
            "listeners": [
                {
                    "listenerArn": "arn:listener/http",
                    "port": 80,
                    "protocol": "HTTP",
                    "defaultActions": [
                        {
                            "type": "forward",
                            "targetGroupArn": "arn:target-group",
                        }
                    ],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    listener_evidence = finding.evidence["listeners"][0]
    assert listener_evidence["port"] == 80


def test_internet_facing_http_with_https_redirect() -> None:
    producer = AwsLoadBalancerPublicHttpProducer()

    resource = _make_resource(
        "arn:aws:elasticloadbalancing:lb/app/redirect",
        "redirect",
    )
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "scheme": "internet-facing",
            "listeners": [
                {
                    "listenerArn": "arn:listener/http",
                    "port": 80,
                    "protocol": "HTTP",
                    "defaultActions": [
                        {
                            "type": "redirect",
                            "redirectConfig": {
                                "Protocol": "HTTPS",
                                "Port": "443",
                                "StatusCode": "HTTP_301",
                            },
                        }
                    ],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []


def test_internal_load_balancer_not_flagged() -> None:
    producer = AwsLoadBalancerPublicHttpProducer()

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
            "listeners": [
                {
                    "listenerArn": "arn:listener/http",
                    "port": 80,
                    "protocol": "HTTP",
                    "defaultActions": [
                        {
                            "type": "forward",
                            "targetGroupArn": "arn:target-group",
                        }
                    ],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []
