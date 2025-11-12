"""Tests for AWS security group public ingress producer."""

from __future__ import annotations

from datetime import datetime

from cerebro.domain.entities import ConfigEntity, ResourceEntity, Severity
from cerebro.findings.producers.aws.security_group_public_ingress import (
    AwsSecurityGroupPublicIngressProducer,
)


def _make_resource(group_id: str, name: str | None = None) -> ResourceEntity:
    return ResourceEntity(
        external_id=group_id,
        resource_type="aws.ec2.security_group",
        provider="aws",
        name=name,
    )


def test_security_group_all_ports_open() -> None:
    producer = AwsSecurityGroupPublicIngressProducer()

    resource = _make_resource("sg-0001", "open-all")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "groupId": "sg-0001",
            "groupName": "open-all",
            "vpcId": "vpc-1",
            "ingressRules": [
                {
                    "ipProtocol": "-1",
                    "fromPort": None,
                    "toPort": None,
                    "ipv4Cidr": ["0.0.0.0/0"],
                    "ipv6Cidr": ["::/0"],
                    "prefixListIds": [],
                    "userIdGroupPairs": [],
                }
            ],
            "egressRules": [],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.CRITICAL
    exposures = finding.evidence["exposures"]
    assert exposures[0]["type"] == "all_ports"


def test_security_group_specific_port_open() -> None:
    producer = AwsSecurityGroupPublicIngressProducer()

    resource = _make_resource("sg-0002", "web-open")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "groupId": "sg-0002",
            "groupName": "web-open",
            "vpcId": "vpc-2",
            "ingressRules": [
                {
                    "ipProtocol": "tcp",
                    "fromPort": 8080,
                    "toPort": 8080,
                    "ipv4Cidr": ["0.0.0.0/0"],
                    "ipv6Cidr": [],
                    "prefixListIds": [],
                    "userIdGroupPairs": [],
                }
            ],
            "egressRules": [],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    exposure = finding.evidence["exposures"][0]
    assert exposure["fromPort"] == 8080
    assert exposure["toPort"] == 8080


def test_security_group_internal_only() -> None:
    producer = AwsSecurityGroupPublicIngressProducer()

    resource = _make_resource("sg-0003", "internal")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "groupId": "sg-0003",
            "groupName": "internal",
            "vpcId": "vpc-3",
            "ingressRules": [
                {
                    "ipProtocol": "tcp",
                    "fromPort": 443,
                    "toPort": 443,
                    "ipv4Cidr": ["10.0.0.0/16"],
                    "ipv6Cidr": [],
                    "prefixListIds": [],
                    "userIdGroupPairs": [],
                }
            ],
            "egressRules": [],
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []
