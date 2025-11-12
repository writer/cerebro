"""Detect cluster-admin bindings granted to broad groups or wildcards."""

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

CRITICAL_GROUPS = {
    "system:authenticated",
    "system:unauthenticated",
    "system:serviceaccounts",
    "system:masters",
    "*",
}


def _is_wildcard_serviceaccount_group(name: str | None) -> bool:
    if not name:
        return False
    return name.startswith("system:serviceaccounts:")


@register_producer
class K8sClusterAdminWildcardBindingProducer(BaseFindingProducer):
    """Detect cluster-admin bindings granted to wide groups or users."""

    @property
    def desired_sources(self) -> set[str]:
        return {"kubernetes"}

    @property
    def resource_types(self) -> set[str]:
        return {"k8s.cluster_role_binding"}

    @property
    def finding_name(self) -> str:
        return "Kubernetes cluster-admin granted to broad principals"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def rule_name(self) -> str:
        return "k8s_cluster_admin_wildcard_binding"

    @property
    def description(self) -> str:
        return "Cluster role binding assigns cluster-admin to broad groups or wildcards"

    @property
    def remediation(self) -> str:
        return (
            "Remove cluster-admin bindings from broad groups or wildcard principals "
            "and replace with scoped roles."
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
        exposures: list[dict[str, Any]] = []
        severity = self.severity

        for subject in subjects:
            kind = subject.get("kind")
            name = subject.get("name")

            if kind == "Group":
                if name in CRITICAL_GROUPS:
                    exposures.append({"type": "group", "name": name, "critical": True})
                elif _is_wildcard_serviceaccount_group(name):
                    exposures.append({"type": "group", "name": name, "critical": True})
            elif kind == "User" and name in {"system:anonymous", "*"}:
                exposures.append({"type": "user", "name": name, "critical": True})

        if not exposures:
            return []

        if any(exposure.get("critical") for exposure in exposures):
            severity = Severity.CRITICAL

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        affected_names = ", ".join(exp.get("name") or "" for exp in exposures)
        summary = "cluster-admin bound to broad principals " f"({affected_names})"

        evidence = {
            "role_ref": role_ref,
            "subjects": subjects,
            "exposures": exposures,
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=("Cluster role binding assigns cluster-admin to broad " "principals"),
            summary=summary,
            evidence=evidence,
            severity=severity,
        )

        return [finding]
