"""Tests for network exposure utility helpers."""

from __future__ import annotations

from cerebro.findings.producers.utils import (
    analyze_instance_network_exposure,
    has_public_interface,
    security_group_rule_allows_public,
)


def test_has_public_interface_by_flag() -> None:
    assert has_public_interface(None, None, flag=True) is True


def test_has_public_interface_detects_public_ip() -> None:
    assert has_public_interface("203.0.113.10", [], flag=False) is True


def test_has_public_interface_private_only_returns_false() -> None:
    assert has_public_interface("10.0.0.5", ["172.16.2.3"], flag=False) is False


def test_security_group_rule_allows_public_port_range() -> None:
    rule = {
        "ipProtocol": "tcp",
        "fromPort": 80,
        "toPort": 443,
        "ipv4Cidr": ["0.0.0.0/0"],
        "ipv6Cidr": [],
    }
    assert security_group_rule_allows_public(rule, 443) is True
    assert security_group_rule_allows_public(rule, 22) is False


def test_security_group_rule_allows_public_all_protocol() -> None:
    rule = {
        "ipProtocol": "-1",
        "fromPort": None,
        "toPort": None,
        "ipv4Cidr": ["0.0.0.0/0"],
        "ipv6Cidr": [],
    }
    assert security_group_rule_allows_public(rule, 22) is True


def test_analyze_instance_network_exposure_with_public_interface() -> None:
    exposure = analyze_instance_network_exposure(
        "i-123",
        {
            "publicIpAddress": "203.0.113.2",
            "networkInterfacePublicIps": [],
            "securityGroups": [],
        },
        target_port=443,
    )
    assert exposure is not None
    assert "public_interface" in exposure["exposureSources"]


def test_analyze_instance_network_exposure_with_security_group() -> None:
    exposure = analyze_instance_network_exposure(
        "i-456",
        {
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
                        }
                    ],
                }
            ],
        },
        target_port=443,
    )
    assert exposure is not None
    assert "security_group" in exposure["exposureSources"]
    assert exposure["securityGroupFindings"][0]["groupId"] == "sg-open"


def test_analyze_instance_network_exposure_without_exposure() -> None:
    exposure = analyze_instance_network_exposure(
        "i-789",
        {
            "networkInterfacePublicIps": ["10.0.0.5"],
            "securityGroups": [
                {
                    "groupId": "sg-private",
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
        target_port=443,
    )
    assert exposure is None
