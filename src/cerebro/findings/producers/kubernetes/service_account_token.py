"""Detect risky service account token usage within Kubernetes pods."""

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
from cerebro.findings.producers.utils import resolve_rule_id


def _is_service_account_token_mount(mount_path: str | None) -> bool:
    if not mount_path:
        return False
    normalized = mount_path.rstrip("/")
    return normalized.startswith("/var/run/secrets/kubernetes.io/serviceaccount")


@register_producer
class K8sServiceAccountTokenExposureProducer(BaseFindingProducer):
    """Detect pods that expose service account tokens by default."""

    @property
    def desired_sources(self) -> set[str]:
        return {"kubernetes"}

    @property
    def resource_types(self) -> set[str]:
        return {"k8s.pod"}

    @property
    def finding_name(self) -> str:
        return "Kubernetes pod exposes service account token"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def rule_name(self) -> str:
        return "k8s_service_account_token_exposure"

    @property
    def description(self) -> str:
        return "Pod mounts service account token with default permissions"

    @property
    def remediation(self) -> str:
        return (
            "Disable automountServiceAccountToken and use scoped service accounts. "
            "Issue short-lived tokens only when workloads need API access."
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        service_account = normalized.get("serviceAccount")
        namespace = normalized.get("namespace")
        automount = normalized.get("automountServiceAccountToken")

        volumes = normalized.get("volumes") or []
        containers = normalized.get("containers") or []

        exposures: list[dict[str, Any]] = []

        if service_account in (None, "", "default"):
            # Pod is using namespace default service account.
            exposures.append(
                {
                    "type": "default_service_account",
                    "serviceAccount": service_account or "default",
                    "namespace": namespace,
                }
            )

        if automount is not False:
            exposures.append(
                {
                    "type": "automount_enabled",
                    "automountServiceAccountToken": automount,
                }
            )

        for container in containers:
            for mount in container.get("volumeMounts") or []:
                mount_path = mount.get("mountPath")
                if _is_service_account_token_mount(mount_path):
                    exposures.append(
                        {
                            "type": "service_account_token_mount",
                            "container": container.get("name"),
                            "path": mount_path,
                        }
                    )

        token_volumes = []
        for volume in volumes:
            for source in volume.get("projectedSources") or []:
                if source.get("type") == "serviceAccountToken":
                    token_volumes.append(
                        {
                            "volume": volume.get("name"),
                            "audience": source.get("audience"),
                            "expirationSeconds": source.get("expirationSeconds"),
                            "path": source.get("path"),
                        }
                    )
        if token_volumes:
            exposures.append(
                {
                    "type": "projected_service_account_token",
                    "tokens": token_volumes,
                }
            )

        if not exposures:
            return []

        severity = self._determine_severity(exposures)

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        summary = self._build_summary(exposures)

        evidence = {
            "namespace": namespace,
            "serviceAccount": service_account or "default",
            "automountServiceAccountToken": automount,
            "exposures": exposures,
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "Kubernetes pod "
                f"{resource.name or resource.external_id} exposes service account token"
            ),
            summary=summary,
            evidence=evidence,
            severity=severity,
        )

        return [finding]

    def _determine_severity(self, exposures: list[dict[str, Any]]) -> Severity:
        default_sa = any(exp["type"] == "default_service_account" for exp in exposures)
        token_mount = any(
            exp["type"] == "service_account_token_mount" for exp in exposures
        )
        projected_token = any(
            exp["type"] == "projected_service_account_token" for exp in exposures
        )

        if default_sa and (token_mount or projected_token):
            return Severity.HIGH
        if token_mount or projected_token:
            return Severity.HIGH
        if default_sa:
            return Severity.MEDIUM
        return self.severity

    def _build_summary(self, exposures: list[dict[str, Any]]) -> str:
        parts: list[str] = []
        for exposure in exposures:
            if exposure["type"] == "default_service_account":
                parts.append("pod uses namespace default service account")
            elif exposure["type"] == "automount_enabled":
                parts.append("automountServiceAccountToken not disabled")
            elif exposure["type"] == "service_account_token_mount":
                container_name = exposure.get("container")
                mount_path = exposure.get("path")
                parts.append(f"container {container_name} mounts token at {mount_path}")
            elif exposure["type"] == "projected_service_account_token":
                tokens = exposure.get("tokens") or []
                audiences = {
                    token.get("audience") for token in tokens if token.get("audience")
                }
                if audiences:
                    parts.append(
                        "projected service account tokens issued for audiences "
                        + ", ".join(sorted(audiences))
                    )
                else:
                    parts.append("projected service account token volume present")

        return "; ".join(parts)
