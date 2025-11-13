"""Detect Kubernetes ingress objects exposing unauthenticated HTTP endpoints."""

from __future__ import annotations

from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import BaseFindingProducer, ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import (
    ProducerRunContext,
    build_network_exposure_evidence,
    downgrade_severity_for_namespace_policy,
    get_namespace_network_posture,
    resolve_rule_id,
)

_FALSEY = {"false", "0", "no", "off", "disabled"}
_TRUEY = {"true", "1", "yes", "on", "enabled"}


def _to_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUEY:
            return True
        if lowered in _FALSEY:
            return False
    return None


def _collect_hosts(rules: list[dict[str, Any]]) -> list[str]:
    hosts: list[str] = []
    for rule in rules or []:
        host = rule.get("host")
        if host:
            hosts.append(host)
    return hosts


@register_producer
class K8sIngressPublicExposureProducer(BaseFindingProducer):
    """Detect ingress resources that expose public HTTP endpoints without TLS."""

    @property
    def desired_sources(self) -> set[str]:  # pragma: no cover - simple property
        return {"kubernetes"}

    @property
    def resource_types(self) -> set[str]:  # pragma: no cover - simple property
        return {"k8s.ingress"}

    @property
    def finding_name(self) -> str:  # pragma: no cover - simple property
        return "Kubernetes ingress exposes public HTTP endpoint"

    @property
    def severity(self) -> Severity:  # pragma: no cover - simple property
        return Severity.HIGH

    @property
    def rule_name(self) -> str:  # pragma: no cover - simple property
        return "k8s_ingress_public_http"

    @property
    def description(self) -> str:  # pragma: no cover - simple property
        return "Ingress exposes a public endpoint without TLS enforcement"

    @property
    def remediation(self) -> str:  # pragma: no cover - simple property
        return (
            "Require TLS for ingress endpoints, disable plaintext HTTP, and add "
            "authentication policies."
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        run_context = ProducerRunContext.ensure(context)

        load_balancer = normalized.get("loadBalancer") or []
        if not load_balancer:
            return []

        annotations = normalized.get("annotations") or {}
        tls_entries = normalized.get("tls") or []
        rules = normalized.get("rules") or []

        allows_http = self._allows_plain_http(annotations)
        forces_https = self._forces_https(annotations)
        insecure_http = allows_http and (not tls_entries or not forces_https)

        if not insecure_http:
            return []

        exposures = [
            {
                "type": "plain_http",
                "hosts": _collect_hosts(rules),
                "load_balancer": load_balancer,
                "public": True,
            }
        ]

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=run_context)

        severity = Severity.CRITICAL if not tls_entries else self.severity

        hosts = _collect_hosts(rules)
        summary_parts = [
            "ingress reachable via load balancer on plaintext HTTP",
        ]
        if hosts:
            summary_parts.append(f"hosts: {', '.join(hosts)}")

        namespace = normalized.get("namespace")
        namespace_posture = get_namespace_network_posture(run_context, namespace)

        severity = downgrade_severity_for_namespace_policy(
            severity,
            namespace_posture=namespace_posture,
            when=Severity.CRITICAL,
            downgrade_to=self.severity,
            require_ingress_default_deny=True,
        )

        evidence = build_network_exposure_evidence(
            namespace=namespace,
            exposures=exposures,
            annotations=annotations,
            namespace_network_posture=namespace_posture,
            ingress_class=normalized.get("ingressClass"),
        )

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "Ingress "
                f"{resource.name or resource.external_id} exposes public HTTP "
                "without TLS"
            ),
            summary="; ".join(summary_parts),
            evidence=evidence,
            severity=severity,
        )

        return [finding]

    def _allows_plain_http(self, annotations: dict[str, Any]) -> bool:
        allow_http = annotations.get("kubernetes.io/ingress.allow-http")
        allow_http_bool = _to_bool(allow_http)
        if allow_http_bool is False:
            return False

        ssl_redirect = annotations.get("nginx.ingress.kubernetes.io/ssl-redirect")
        ssl_redirect_bool = _to_bool(ssl_redirect)
        if ssl_redirect_bool is False:
            return True

        return True

    def _forces_https(self, annotations: dict[str, Any]) -> bool:
        force_ssl = annotations.get("nginx.ingress.kubernetes.io/force-ssl-redirect")
        force_ssl_bool = _to_bool(force_ssl)
        if force_ssl_bool is True:
            return True

        legacy_force = annotations.get("ingress.kubernetes.io/force-ssl-redirect")
        legacy_force_bool = _to_bool(legacy_force)
        if legacy_force_bool is True:
            return True

        return False
