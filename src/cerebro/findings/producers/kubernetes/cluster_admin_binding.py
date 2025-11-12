"""Detect cluster role bindings that grant cluster-admin to service accounts."""

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

CRITICAL_NAMESPACES = {"kube-system", "kube-public", "default"}


def _get_service_account_subjects(
    subjects: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    service_accounts: list[dict[str, Any]] = []
    for subject in subjects:
        if subject.get("kind") == "ServiceAccount":
            service_accounts.append(subject)
    return service_accounts


@register_producer
class K8sClusterAdminServiceAccountProducer(BaseFindingProducer):
    """Detect cluster-admin bindings granted to service accounts."""

    @property
    def desired_sources(self) -> set[str]:
        return {"kubernetes"}

    @property
    def resource_types(self) -> set[str]:
        return {"k8s.cluster_role_binding"}

    @property
    def finding_name(self) -> str:
        return "Kubernetes cluster-admin granted to service account"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def rule_name(self) -> str:
        return "k8s_cluster_admin_service_account"

    @property
    def description(self) -> str:
        return "Cluster role binding assigns cluster-admin to a service account"

    @property
    def remediation(self) -> str:
        return (
            "Replace broad cluster-admin bindings with least-privilege roles and use "
            "namespace-scoped role bindings."
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        role_ref = normalized.get("roleRef") or {}

        if (
            role_ref.get("kind") != "ClusterRole"
            or role_ref.get("name") != "cluster-admin"
        ):
            return []

        subjects = normalized.get("subjects") or []
        service_accounts = _get_service_account_subjects(subjects)
        if not service_accounts:
            return []

        exposures: list[dict[str, Any]] = []
        critical = False
        for subject in service_accounts:
            namespace = subject.get("namespace")
            exposure = {
                "name": subject.get("name"),
                "namespace": namespace,
            }
            if namespace in CRITICAL_NAMESPACES:
                critical = True
                exposure["critical"] = True
            exposures.append(exposure)

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        severity = Severity.CRITICAL if critical else self.severity

        services = [
            f"{exposure.get('namespace') or 'cluster'}:{exposure.get('name')}"
            for exposure in exposures
        ]

        summary = "cluster-admin granted to service accounts " f"{', '.join(services)}"

        evidence = {
            "role_ref": role_ref,
            "service_accounts": exposures,
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=("Cluster role binding assigns cluster-admin to service " "account"),
            summary=summary,
            evidence=evidence,
            severity=severity,
        )

        return [finding]
