"""Tests for load balancer target exposure producer."""

from __future__ import annotations

from datetime import datetime, timezone

from cerebro.domain.entities import ConfigEntity, ResourceEntity, Severity
from cerebro.findings.producers.aws.load_balancer_target_exposure import (
    AwsLoadBalancerTargetExposureProducer,
)


def _make_resource(lb_arn: str, scheme: str = "internet-facing") -> ResourceEntity:
    return ResourceEntity(
        external_id=lb_arn,
        resource_type="aws.elbv2.load_balancer",
        provider="aws",
        name="alb",
        metadata={"scheme": scheme},
    )


def test_public_ip_target_flagged() -> None:
    producer = AwsLoadBalancerTargetExposureProducer()
    resource = _make_resource("arn:aws:elasticloadbalancing:lb/app/public")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.now(timezone.utc),  # noqa: UP017
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "scheme": "internet-facing",
            "listeners": [
                {
                    "listenerArn": "arn:listener/https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "defaultActions": [
                        {
                            "type": "forward",
                            "targetGroupArn": "arn:target-group/public-ip",
                        }
                    ],
                }
            ],
            "targetGroups": [
                {
                    "targetGroupArn": "arn:target-group/public-ip",
                    "targetType": "ip",
                    "targets": [
                        {
                            "id": "8.8.8.8",
                            "port": 80,
                        }
                    ],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    exposure = findings[0].evidence["exposures"][0]
    assert exposure["publicTargets"] == ["8.8.8.8"]


def test_private_ip_target_not_flagged() -> None:
    producer = AwsLoadBalancerTargetExposureProducer()
    resource = _make_resource("arn:aws:elasticloadbalancing:lb/app/private")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.now(timezone.utc),  # noqa: UP017
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
                            "targetGroupArn": "arn:target-group/private",
                        }
                    ],
                }
            ],
            "targetGroups": [
                {
                    "targetGroupArn": "arn:target-group/private",
                    "targetType": "ip",
                    "targets": [
                        {
                            "id": "10.0.1.5",
                            "port": 8080,
                        }
                    ],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []


def test_instance_target_with_public_interface_flagged() -> None:
    producer = AwsLoadBalancerTargetExposureProducer()
    resource = _make_resource("arn:aws:elasticloadbalancing:lb/app/instance-public")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.now(timezone.utc),  # noqa: UP017
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "scheme": "internet-facing",
            "listeners": [
                {
                    "listenerArn": "arn:listener/https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "defaultActions": [
                        {
                            "type": "forward",
                            "targetGroupArn": "arn:target-group/instance-public",
                        }
                    ],
                }
            ],
            "targetGroups": [
                {
                    "targetGroupArn": "arn:target-group/instance-public",
                    "targetType": "instance",
                    "targets": [
                        {
                            "id": "i-1234567890abcdef0",
                            "instance": {
                                "publicIpAddress": "8.8.4.4",
                                "networkInterfacePublicIps": ["8.8.4.4"],
                                "hasPublicInterface": True,
                                "publicDnsName": "example.amazonaws.com",
                            },
                        }
                    ],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    exposure = findings[0].evidence["exposures"][0]
    assert exposure["targetType"] == "instance"
    assert exposure["publicInstances"][0]["instanceId"] == "i-1234567890abcdef0"


def test_instance_target_without_public_interface_not_flagged() -> None:
    producer = AwsLoadBalancerTargetExposureProducer()
    resource = _make_resource("arn:aws:elasticloadbalancing:lb/app/instance-private")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.now(timezone.utc),  # noqa: UP017
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
                            "targetGroupArn": "arn:target-group/instance-private",
                        }
                    ],
                }
            ],
            "targetGroups": [
                {
                    "targetGroupArn": "arn:target-group/instance-private",
                    "targetType": "instance",
                    "targets": [
                        {
                            "id": "i-0abcdef1234567890",
                            "instance": {
                                "hasPublicInterface": False,
                                "networkInterfacePublicIps": [],
                                "securityGroups": [
                                    {
                                        "groupId": "sg-closed",
                                        "ingressRules": [
                                            {
                                                "ipProtocol": "tcp",
                                                "fromPort": 443,
                                                "toPort": 443,
                                                "ipv4Cidr": ["10.0.0.0/16"],
                                                "ipv6Cidr": [],
                                            }
                                        ],
                                    }
                                ],
                            },
                        }
                    ],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []


def test_instance_target_with_open_security_group_flagged() -> None:
    producer = AwsLoadBalancerTargetExposureProducer()
    resource = _make_resource("arn:aws:elasticloadbalancing:lb/app/instance-sg")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.now(timezone.utc),  # noqa: UP017
        normalized_config={
            "loadBalancerArn": resource.external_id,
            "scheme": "internet-facing",
            "listeners": [
                {
                    "listenerArn": "arn:listener/https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "defaultActions": [
                        {
                            "type": "forward",
                            "targetGroupArn": "arn:target-group/instance-sg",
                        }
                    ],
                }
            ],
            "targetGroups": [
                {
                    "targetGroupArn": "arn:target-group/instance-sg",
                    "targetType": "instance",
                    "port": 443,
                    "targets": [
                        {
                            "id": "i-0feedfeed12345678",
                            "instance": {
                                "hasPublicInterface": False,
                                "publicIpAddress": None,
                                "networkInterfacePublicIps": [],
                                "securityGroups": [
                                    {
                                        "groupId": "sg-open",
                                        "ingressRules": [
                                            {
                                                "ipProtocol": "tcp",
                                                "fromPort": 80,
                                                "toPort": 443,
                                                "ipv4Cidr": ["0.0.0.0/0"],
                                                "ipv6Cidr": [],
                                            },
                                            {
                                                "ipProtocol": "udp",
                                                "fromPort": None,
                                                "toPort": None,
                                                "ipv4Cidr": ["192.168.0.0/16"],
                                                "ipv6Cidr": [],
                                            },
                                        ],
                                    }
                                ],
                            },
                        }
                    ],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    exposure = findings[0].evidence["exposures"][0]
    instance_exposure = exposure["publicInstances"][0]
    assert "security_group" in instance_exposure["exposureSources"]
    assert instance_exposure["securityGroupFindings"][0]["groupId"] == "sg-open"


def test_internal_load_balancer_not_flagged() -> None:
    producer = AwsLoadBalancerTargetExposureProducer()
    resource = _make_resource(
        "arn:aws:elasticloadbalancing:lb/app/internal",
        "internal",
    )
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.now(timezone.utc),  # noqa: UP017
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
                            "targetGroupArn": "arn:target-group/public-ip",
                        }
                    ],
                }
            ],
            "targetGroups": [
                {
                    "targetGroupArn": "arn:target-group/public-ip",
                    "targetType": "ip",
                    "targets": [
                        {
                            "id": "8.8.8.8",
                            "port": 80,
                        }
                    ],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []
