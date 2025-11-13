"""Tests for AWS security group administrative port exposure producer."""

from __future__ import annotations

from datetime import datetime

from cerebro.domain.entities import ConfigEntity, ResourceEntity, Severity
from cerebro.findings.producers.aws.security_group_admin_port import (
    AwsSecurityGroupAdminPortProducer,
)


def _make_resource(group_id: str, name: str | None = None) -> ResourceEntity:
    return ResourceEntity(
        external_id=group_id,
        resource_type="aws.ec2.security_group",
        provider="aws",
        name=name,
    )


def test_security_group_exposes_ssh() -> None:
    producer = AwsSecurityGroupAdminPortProducer()

    resource = _make_resource("sg-123", "admin-ssh")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "groupId": "sg-123",
            "groupName": "admin-ssh",
            "vpcId": "vpc-1",
            "ingressRules": [
                {
                    "ipProtocol": "tcp",
                    "fromPort": 22,
                    "toPort": 22,
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
    rules = finding.evidence["public_rules"]
    assert rules[0]["from_port"] == 22
    assert rules[0]["metadata"]["service"] == "SSH"


def test_security_group_restricted_ingress() -> None:
    producer = AwsSecurityGroupAdminPortProducer()

    resource = _make_resource("sg-456", "restricted")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "groupId": "sg-456",
            "groupName": "restricted",
            "vpcId": "vpc-2",
            "ingressRules": [
                {
                    "ipProtocol": "tcp",
                    "fromPort": 22,
                    "toPort": 22,
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


def test_security_group_all_ports_open() -> None:
    producer = AwsSecurityGroupAdminPortProducer()

    resource = _make_resource("sg-789", "any-port")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "groupId": "sg-789",
            "groupName": "any-port",
            "vpcId": "vpc-3",
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
    assert finding.severity == Severity.HIGH
    ports = {rule["from_port"] for rule in finding.evidence["public_rules"]}
    assert 22 in ports and 3389 in ports
