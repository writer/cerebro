"""Detect namespaces lacking restrictive network policies."""

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


@register_producer
class K8sNamespaceNetworkPolicyProducer(BaseFindingProducer):
    """Identify namespaces without default-deny ingress or egress policies."""

    @property
    def desired_sources(self) -> set[str]:
        return {"kubernetes"}

    @property
    def resource_types(self) -> set[str]:
        return {"k8s.namespace"}

    @property
    def finding_name(self) -> str:
        return "Kubernetes namespace lacks restrictive network policy"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def rule_name(self) -> str:
        return "k8s_namespace_network_policy_gap"

    @property
    def description(self) -> str:
        return "Namespace does not enforce default deny network policies"

    @property
    def remediation(self) -> str:
        return (
            "Create default deny ingress and egress NetworkPolicies that select "
            "all pods and explicitly allow required traffic."
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        namespace = normalized.get("name") or resource.external_id
        policies = normalized.get("networkPolicies") or []

        exposures: list[dict[str, Any]] = []

        if not policies:
            exposures.append({"type": "missing_network_policies"})
        else:
            has_ingress_policy = False
            has_egress_policy = False
            default_deny_ingress = False
            default_deny_egress = False

            for policy in policies:
                policy_types = set(policy.get("policyTypes") or [])
                selects_all = bool(policy.get("selectsAllPods"))
                ingress_count = policy.get("ingressRuleCount", 0)
                egress_count = policy.get("egressRuleCount", 0)

                if "Ingress" in policy_types:
                    has_ingress_policy = True
                    if selects_all and ingress_count == 0:
                        default_deny_ingress = True

                if "Egress" in policy_types:
                    has_egress_policy = True
                    if selects_all and egress_count == 0:
                        default_deny_egress = True

            if not has_ingress_policy:
                exposures.append({"type": "missing_ingress_policy"})
            elif not default_deny_ingress:
                exposures.append({"type": "missing_default_deny_ingress"})

            if not has_egress_policy:
                exposures.append({"type": "missing_egress_policy"})
            elif not default_deny_egress:
                exposures.append({"type": "missing_default_deny_egress"})

        if not exposures:
            return []

        severity = self._determine_severity(exposures)

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        evidence = {
            "namespace": namespace,
            "policyCount": len(policies),
            "exposures": exposures,
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "Kubernetes namespace "
                f"{namespace} lacks restrictive network policies"
            ),
            summary=self._build_summary(exposures),
            evidence=evidence,
            severity=severity,
        )

        return [finding]

    def _determine_severity(self, exposures: list[dict[str, Any]]) -> Severity:
        exposure_types = {exposure["type"] for exposure in exposures}
        if "missing_network_policies" in exposure_types:
            return Severity.HIGH
        if "missing_ingress_policy" in exposure_types:
            return Severity.HIGH
        if "missing_default_deny_ingress" in exposure_types:
            return Severity.HIGH
        if "missing_default_deny_egress" in exposure_types:
            return Severity.MEDIUM
        return self.severity

    def _build_summary(self, exposures: list[dict[str, Any]]) -> str:
        descriptions: list[str] = []
        for exposure in exposures:
            exposure_type = exposure["type"]
            if exposure_type == "missing_network_policies":
                descriptions.append("no NetworkPolicies defined")
            elif exposure_type == "missing_ingress_policy":
                descriptions.append("no ingress NetworkPolicy defined")
            elif exposure_type == "missing_default_deny_ingress":
                descriptions.append("ingress is not default denied")
            elif exposure_type == "missing_egress_policy":
                descriptions.append("no egress NetworkPolicy defined")
            elif exposure_type == "missing_default_deny_egress":
                descriptions.append("egress is not default denied")

        return "; ".join(descriptions)
