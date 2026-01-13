"""Producer for detecting GKE clusters using default service account."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import resolve_rule_id

from .base import BaseGCPProducer


@register_producer
class GKEDefaultServiceAccountProducer(BaseGCPProducer):
    """Detect GKE clusters using the default Compute Engine service account.

    The default service account has broad permissions. GKE workloads should
    use dedicated service accounts with minimal permissions.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"gcp.gke.cluster", "gcp.container.cluster"}

    @property
    def finding_name(self) -> str:
        return "GCP: GKE Cluster Using Default Service Account"

    @property
    def rule_name(self) -> str:
        return "gcp_gke_default_service_account"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return (
            "GKE cluster node pools are configured to use the default Compute Engine "
            "service account, which has excessive permissions."
        )

    @property
    def remediation(self) -> str:
        return (
            "Create a dedicated service account with minimal permissions for GKE. "
            "Use Workload Identity to bind Kubernetes service accounts to GCP service accounts. "
            "Apply least-privilege IAM bindings to the service account."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-6", "AC-6(1)", "CM-7"],
            "cwe": ["CWE-250", "CWE-269"],
            "cis_gcp": ["7.17"],
            "mitre_attack": ["T1078.004"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate GKE cluster for default service account usage."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check node pools for service account configuration
        node_pools = data.get("node_pools", []) or []
        node_config = data.get("node_config", {}) or {}

        # Track node pools using default service account
        default_sa_pools: list[dict[str, Any]] = []

        # Check cluster-level node config
        cluster_sa = node_config.get("service_account", "")
        if _is_default_service_account(cluster_sa):
            default_sa_pools.append({
                "name": "default-pool",
                "service_account": cluster_sa,
                "level": "cluster",
            })

        # Check individual node pools
        for pool in node_pools:
            if not isinstance(pool, dict):
                continue

            pool_name = pool.get("name", "unknown")
            pool_config = pool.get("config", {}) or {}
            pool_sa = pool_config.get("service_account", "")

            if _is_default_service_account(pool_sa):
                default_sa_pools.append({
                    "name": pool_name,
                    "service_account": pool_sa,
                    "level": "node_pool",
                })

        if not default_sa_pools:
            return findings

        # Build risk factors
        risk_factors: list[str] = ["using_default_service_account"]

        # Check for Workload Identity
        workload_identity = data.get("workload_identity_config")
        if not workload_identity:
            risk_factors.append("workload_identity_disabled")

        # Check for Shielded GKE Nodes
        shielded_nodes = data.get("shielded_nodes", {})
        if not shielded_nodes.get("enabled", False):
            risk_factors.append("shielded_nodes_disabled")

        # Check Binary Authorization
        binary_auth = data.get("binary_authorization", {})
        if not binary_auth.get("enabled", False):
            risk_factors.append("binary_auth_disabled")

        # Determine severity
        severity = self.severity
        if len(default_sa_pools) > 1 or not workload_identity:
            severity = Severity.HIGH

        evidence = {
            "cluster_name": resource.name,
            "cluster_id": resource.external_id,
            "project_id": data.get("project_id") or data.get("project"),
            "location": data.get("location") or data.get("zone"),
            "default_sa_node_pools": default_sa_pools,
            "total_node_pools": len(node_pools),
            "workload_identity_enabled": bool(workload_identity),
            "shielded_nodes_enabled": shielded_nodes.get("enabled", False),
            "binary_auth_enabled": binary_auth.get("enabled", False),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        pool_names = ", ".join(p["name"] for p in default_sa_pools[:3])

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"GKE cluster {resource.name} uses default service account",
                summary=(
                    f"Node pools using default SA: {pool_names}. "
                    f"Risk factors: {', '.join(risk_factors)}"
                ),
                evidence=evidence,
                severity=severity,
            )
        )

        return findings


def _is_default_service_account(service_account: str) -> bool:
    """Check if service account is the default Compute Engine SA."""
    if not service_account:
        return True  # No SA specified defaults to Compute Engine default

    sa_lower = service_account.lower()
    return (
        "compute@developer.gserviceaccount.com" in sa_lower
        or "default" in sa_lower
        or service_account == ""
    )
