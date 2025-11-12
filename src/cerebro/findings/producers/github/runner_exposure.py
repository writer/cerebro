"""Producers covering GitHub Actions runner exposures."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, cast

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import (
    build_runner_group_exposure,
    build_runner_host_exposure,
    coerce_mapping,
    resolve_rule_id,
)
from cerebro.telemetry.schemas import HostTelemetry, NetworkConnection

from .base import BaseGitHubProducer


def _get_value(
    source: Mapping[str, Any] | HostTelemetry,
    key: str,
    default: Any = None,
) -> Any:
    if isinstance(source, Mapping):
        return source.get(key, default)
    return getattr(source, key, default)


def _is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or address.is_link_local)


def _iter_public_ips(ips: Iterable[str]) -> list[str]:
    return [ip for ip in ips if _is_public_ip(ip)]


def _normalize_network_connections(
    connections: Sequence[NetworkConnection | Mapping[str, Any]] | None,
) -> list[NetworkConnection]:
    results: list[NetworkConnection] = []
    if not connections:
        return results

    for item in connections:
        if isinstance(item, NetworkConnection):
            results.append(item)
        elif isinstance(item, Mapping):
            try:
                results.append(NetworkConnection(**item))
            except (TypeError, ValueError):  # pragma: no cover - defensive
                continue
    return results


def _coerce_mapping_sequence(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [item for item in value if isinstance(item, Mapping)]
    mapping = coerce_mapping(value)
    return [mapping] if mapping is not None else []


@register_producer
class GithubRunnerPublicExposureProducer(BaseGitHubProducer):
    """Detect runners that can be used by public repositories."""

    @property
    def resource_types(self) -> set[str]:
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
    def framework_mappings(self) -> dict[str, list[str]]:
        mappings: dict[str, list[str]] = {
            key: list(value) for key, value in super().framework_mappings.items()
        }
        mappings.setdefault("cis", []).append("4.2.1")
        mappings.setdefault("nist_800_53", []).extend(["CM-6", "SC-7"])
        return mappings

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        runner = coerce_mapping(normalized.get("runner")) or {}
        runner_group = coerce_mapping(normalized.get("runner_group")) or {}
        repositories = _coerce_mapping_sequence(normalized.get("repositories"))

        runner.setdefault("id", runner.get("id") or resource.external_id)
        runner.setdefault("name", runner.get("name") or resource.name)

        if runner.get("ephemeral") is True:
            return []

        allows_public_repos = runner_group.get("allows_public_repositories")
        visibility = runner_group.get("visibility")

        public_repos = [
            repo for repo in repositories if repo.get("visibility") == "public"
        ]

        if (
            not allows_public_repos
            and visibility not in {"all", "public"}
            and not public_repos
        ):
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        evidence = build_runner_group_exposure(
            runner=runner,
            runner_group=runner_group,
            exposed_repositories=public_repos,
        )

        summary = (
            "Runner "
            f"{runner.get('name') or resource.name} is assigned to group "
            f"'{runner_group.get('name')}' which permits public repositories."
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
    def resource_types(self) -> set[str]:
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
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        if not context:
            return []

        telemetry_index_obj = context.get("host_telemetry_index")
        if not telemetry_index_obj:
            return []

        runner = coerce_mapping((config.normalized_config or {}).get("runner")) or {}
        runner_name = runner.get("name") or resource.name

        runner.setdefault("id", runner.get("id") or resource.external_id)
        runner.setdefault("name", runner_name)

        host: Mapping[str, Any] | HostTelemetry | None = None
        if isinstance(telemetry_index_obj, Mapping):
            host = telemetry_index_obj.get(runner_name)
            if not host:
                host = telemetry_index_obj.get((runner_name or "").lower())

        if not host:
            return []

        ip_addresses = cast(Iterable[str], _get_value(host, "ip_addresses", []) or [])
        public_ips = _iter_public_ips(ip_addresses)
        if not public_ips:
            return []

        network_connections = _normalize_network_connections(
            cast(
                Sequence[NetworkConnection | Mapping[str, Any]] | None,
                _get_value(host, "network_connections"),
            )
        )

        listening_ports = [
            conn.local_port
            for conn in network_connections
            if conn.local_port in {22, 3389}
            and (conn.status or "").upper().startswith("LISTEN")
        ]

        if not listening_ports:
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        host_context = {
            "host_id": _get_value(host, "host_id"),
            "hostname": _get_value(host, "hostname"),
        }

        evidence = build_runner_host_exposure(
            runner=runner,
            host=host_context,
            public_ips=public_ips,
            listening_ports=listening_ports,
        )

        summary = (
            "Runner host "
            f"{runner_name} listens on {listening_ports} while exposed to public IPs"
        )

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            summary=summary,
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
