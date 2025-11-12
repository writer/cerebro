"""Reusable network exposure analysis helpers for findings producers."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

PUBLIC_IPV4_CIDR = "0.0.0.0/0"
PUBLIC_IPV6_CIDR = "::/0"


def has_public_interface(
    public_ip: str | None,
    interface_ips: Iterable[str] | None,
    flag: bool | None = None,
) -> bool:
    """Return True when the instance has a public network interface."""

    if flag:
        return True

    if public_ip and _is_public_ip(public_ip):
        return True

    for ip in interface_ips or []:
        if _is_public_ip(ip):
            return True

    return False


def security_group_rule_allows_public(
    rule: dict[str, Any],
    target_port: int | None,
) -> bool:
    """Return True when a security group rule exposes a port publicly."""

    ipv4_cidrs = rule.get("ipv4Cidr") or []
    ipv6_cidrs = rule.get("ipv6Cidr") or []
    has_public_cidr = any(cidr == PUBLIC_IPV4_CIDR for cidr in ipv4_cidrs) or any(
        cidr == PUBLIC_IPV6_CIDR for cidr in ipv6_cidrs
    )
    if not has_public_cidr:
        return False

    protocol = rule.get("ipProtocol")
    from_port = rule.get("fromPort")
    to_port = rule.get("toPort")

    if protocol in {None, "-1"}:
        return True

    protocol_str = str(protocol).lower()
    if protocol_str not in {"tcp", "udp", "all"}:
        return False

    if target_port is None:
        return True

    if from_port is None and to_port is None:
        return True

    if from_port is None:
        from_port = to_port
    if to_port is None:
        to_port = from_port

    if from_port is None or to_port is None:
        return True

    try:
        return int(from_port) <= int(target_port) <= int(to_port)
    except TypeError:
        return False


def analyze_instance_network_exposure(
    instance_id: str | None,
    instance_details: dict[str, Any] | None,
    target_port: int | None,
) -> dict[str, Any] | None:
    """Inspect an instance target and return exposure evidence, if any."""

    if not instance_details:
        return None

    public_ip = instance_details.get("publicIpAddress")
    interface_ips = instance_details.get("networkInterfacePublicIps") or []
    has_interface = has_public_interface(
        public_ip,
        interface_ips,
        flag=instance_details.get("hasPublicInterface"),
    )

    security_group_findings: list[dict[str, Any]] = []
    for security_group in instance_details.get("securityGroups") or []:
        group_id = security_group.get("groupId")
        for rule in security_group.get("ingressRules") or []:
            if security_group_rule_allows_public(rule, target_port):
                security_group_findings.append(
                    {
                        "groupId": group_id,
                        "ipProtocol": rule.get("ipProtocol"),
                        "fromPort": rule.get("fromPort"),
                        "toPort": rule.get("toPort"),
                        "ipv4Cidr": rule.get("ipv4Cidr"),
                        "ipv6Cidr": rule.get("ipv6Cidr"),
                    }
                )

    exposure_sources: list[str] = []
    if has_interface:
        exposure_sources.append("public_interface")
    if security_group_findings:
        exposure_sources.append("security_group")

    if not exposure_sources:
        return None

    return {
        "instanceId": instance_id,
        "publicIpAddress": public_ip,
        "interfacePublicIps": interface_ips,
        "publicDnsName": instance_details.get("publicDnsName"),
        "subnetId": instance_details.get("subnetId"),
        "vpcId": instance_details.get("vpcId"),
        "exposureSources": exposure_sources,
        "securityGroupFindings": security_group_findings,
    }


def _is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    value = value.strip()
    if not value:
        return False
    # Simple heuristic: treat RFC 1918 and link-local ranges as non-public.
    for prefix in ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                   "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                   "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
                   "172.31.", "192.168.", "169.254."):
        if value.startswith(prefix):
            return False
    return True
