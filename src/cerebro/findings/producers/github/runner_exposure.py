"""Producers covering GitHub Actions runner exposures."""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Sequence, Set, Union

from cerebro.domain.entities import ConfigEntity, FindingEntity, ResourceEntity, Severity
from cerebro.findings.producers.registry import register_producer
from cerebro.telemetry.schemas import HostTelemetry, NetworkConnection

from .base import BaseGitHubProducer


def _get_value(source: Union[Dict[str, object], HostTelemetry], key: str, default=None):
    if isinstance(source, dict):
        return source.get(key, default)
    return getattr(source, key, default)


def _is_public_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or address.is_link_local)


def _iter_public_ips(ips: Sequence[str]) -> List[str]:
    return [ip for ip in ips if _is_public_ip(ip)]


def _normalize_network_connections(connections: Optional[Sequence]) -> List[NetworkConnection]:
    results: List[NetworkConnection] = []
    if not connections:
        return results

    for item in connections:
        if isinstance(item, NetworkConnection):
            results.append(item)
        elif isinstance(item, dict):
            try:
                results.append(NetworkConnection(**item))
            except Exception:
                continue
    return results


@register_producer
class GithubRunnerPublicExposureProducer(BaseGitHubProducer):
    """Detect runners that can be used by public repositories."""

    @property
    def resource_types(self) -> Set[str]:
        return {"github.runner"}

    @property
    def finding_name(self) -> str:
        return "GitHub Actions runner exposed to public repositories"

    @property
    def rule_name(self) -> str:
        return "github_runner_public_repository_exposure"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        mappings = super().framework_mappings
        mappings.setdefault("cis", []).append("4.2.1")
        mappings.setdefault("nist_800_53", []).extend(["CM-6", "SC-7"])
        return mappings

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, object]] = None,
    ) -> List[FindingEntity]:
        normalized = config.normalized_config or {}
        runner = normalized.get("runner", {})
        runner_group = normalized.get("runner_group", {}) or {}
        repositories = normalized.get("repositories", []) or []

        if runner.get("ephemeral") is True:
            return []

        allows_public_repos = runner_group.get("allows_public_repositories")
        visibility = runner_group.get("visibility")

        public_repos = [repo for repo in repositories if repo.get("visibility") == "public"]

        if not allows_public_repos and visibility not in {"all", "public"} and not public_repos:
            return []

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        evidence = {
            "runner": {
                "id": runner.get("id") or resource.external_id,
                "name": runner.get("name") or resource.name,
                "os": runner.get("os"),
                "labels": runner.get("labels"),
            },
            "runner_group": {
                "id": runner_group.get("id"),
                "name": runner_group.get("name"),
                "visibility": visibility,
                "allows_public_repositories": allows_public_repos,
            },
            "exposed_repositories": public_repos[:10],
        }

        summary = (
            f"Runner {runner.get('name') or resource.name} is assigned to group"
            f" '{runner_group.get('name')}' which permits public repositories."
        )

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            summary=summary,
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]


@register_producer
class GithubRunnerNetworkExposureProducer(BaseGitHubProducer):
    """Detect runners with public network exposure and remote management ports."""

    @property
    def resource_types(self) -> Set[str]:
        return {"github.runner"}

    @property
    def finding_name(self) -> str:
        return "GitHub Actions runner exposes remote management services"

    @property
    def rule_name(self) -> str:
        return "github_runner_public_network_exposure"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, object]] = None,
    ) -> List[FindingEntity]:
        if not context:
            return []

        telemetry_index = context.get("host_telemetry_index")
        if not telemetry_index:
            return []

        runner = (config.normalized_config or {}).get("runner", {})
        runner_name = runner.get("name") or resource.name

        host = telemetry_index.get(runner_name) if isinstance(telemetry_index, dict) else None
        if not host and isinstance(telemetry_index, dict):
            host = telemetry_index.get((runner_name or "").lower())

        if not host:
            return []

        ip_addresses = _get_value(host, "ip_addresses", []) or []
        public_ips = _iter_public_ips(ip_addresses)
        if not public_ips:
            return []

        network_connections = _normalize_network_connections(_get_value(host, "network_connections"))

        listening_ports = [
            conn.local_port
            for conn in network_connections
            if conn.local_port in {22, 3389}
            and (conn.status or "").upper().startswith("LISTEN")
        ]

        if not listening_ports:
            return []

        rule_id = context.get("rule_id")
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        evidence = {
            "runner": {
                "id": runner.get("id") or resource.external_id,
                "name": runner_name,
                "labels": runner.get("labels"),
            },
            "host": {
                "host_id": _get_value(host, "host_id"),
                "hostname": _get_value(host, "hostname"),
                "public_ips": public_ips,
                "listening_ports": listening_ports,
            },
        }

        summary = (
            f"Runner host {runner_name} listens on {listening_ports} while exposed to public IPs"
        )

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            summary=summary,
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
