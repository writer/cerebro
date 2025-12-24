"""Attack graph scoring service."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.models import Principal, Resource
from .service_identity import ServiceIdentityEdge, TrustMechanism

DEFAULT_CONFIG: dict[str, Any] = {
    "principal": {
        "base": 0.5,
        "service_account_bonus": 0.2,
        "inactive_bonus": 0.3,
        "external_bonus": 0.1,
    },
    "resource": {
        "base": 0.3,
        "high_risk_types": {
            "secret": 0.7,
            "key": 0.6,
            "database": 0.6,
            "bucket": 0.4,
        },
        "production_bonus": 0.3,
    },
    "edge": {
        "privilege_weights": {
            "owner": 0.2,
            "admin": 0.25,
            "write": 0.4,
            "read": 0.7,
            "default": 0.5,
        },
        "mechanism_weights": {
            TrustMechanism.OIDC_FEDERATION.value: 0.3,
            TrustMechanism.WORKLOAD_IDENTITY.value: 0.35,
            TrustMechanism.INSTANCE_METADATA.value: 0.45,
            TrustMechanism.SECRET_INJECTION.value: 0.25,
            "default": 0.5,
        },
    },
    "privilege_levels": {
        "owner": 3,
        "admin": 3,
        "root": 3,
        "superuser": 3,
        "write": 2,
        "modify": 2,
        "delete": 2,
        "create": 2,
        "read": 1,
        "view": 1,
        "list": 1,
        "default": 1,
    },
}


def _lookup(mapping: dict[str, Any], key: str, default_key: str = "default") -> Any:
    for candidate in mapping:
        if candidate != default_key and candidate in key:
            return mapping[candidate]
    return mapping.get(default_key)


def _deep_merge(target: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    merged = dict(target)
    for key, value in source.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


@dataclass
class AttackGraphScoring:
    config: dict[str, Any] | None = None
    _edge_config: dict[str, Any] = field(init=False, repr=False, default_factory=dict)
    _principal_config: dict[str, Any] = field(
        init=False, repr=False, default_factory=dict
    )
    _resource_config: dict[str, Any] = field(
        init=False, repr=False, default_factory=dict
    )
    _privilege_levels: dict[str, Any] = field(
        init=False, repr=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        user_config = self.config or {}
        self.config = _deep_merge(DEFAULT_CONFIG, user_config)
        self._edge_config = self.config.get("edge", {})
        self._principal_config = self.config.get("principal", {})
        self._resource_config = self.config.get("resource", {})
        self._privilege_levels = self.config.get("privilege_levels", {})

    def principal_risk(self, principal: Principal) -> float:
        base = self._principal_config.get("base", 0.5)
        if principal.principal_type == "service_account":
            base += self._principal_config.get("service_account_bonus", 0.2)
        is_active = getattr(principal, "is_active", True)
        if not is_active:
            base += self._principal_config.get("inactive_bonus", 0.3)
        if principal.provider and principal.provider != "internal":
            base += self._principal_config.get("external_bonus", 0.1)
        return min(base, 1.0)

    def principal_criticality(self, principal: Principal) -> str:
        if principal.principal_type == "service_account":
            return "high"
        is_active = getattr(principal, "is_active", True)
        if not is_active:
            return "medium"
        return "low"

    def resource_risk(self, resource: Resource) -> float:
        base = self._resource_config.get("base", 0.3)
        risk_types: dict[str, float] = self._resource_config.get("high_risk_types", {})
        for pattern, bonus in risk_types.items():
            if pattern in resource.resource_type.lower():
                base += bonus
        metadata_str = str(resource.metadata or "").lower()
        if "prod" in metadata_str or "production" in metadata_str:
            base += self._resource_config.get("production_bonus", 0.3)
        return min(base, 1.0)

    def resource_criticality(self, resource: Resource) -> str:
        resource_type = resource.resource_type.lower()
        high = self._resource_config.get("high_risk_types", {}).keys()
        if any(term in resource_type for term in ("secret", "key", "database")):
            return "critical"
        if any(term in resource_type for term in ("bucket", "storage", "compute")):
            return "high"
        if any(term in resource_type for term in high):
            return "high"
        return "medium"

    def edge_weight(
        self, permission: str, provider: str, *, mechanism: str | None = None
    ) -> float:
        privilege_weights = self._edge_config.get("privilege_weights", {})
        mechanism_weights = self._edge_config.get("mechanism_weights", {})

        permission_lower = permission.lower()
        base = (
            _lookup(privilege_weights, permission_lower, default_key="default") or 0.5
        )

        if mechanism:
            mech_weight = mechanism_weights.get(mechanism) or mechanism_weights.get(
                "default"
            )
            if mech_weight is not None:
                base = min((base + mech_weight) / 2, 1.0)

        if provider in ("github_actions", "ci_cd"):
            base = min(base * 0.8, 1.0)

        return base

    def privilege_level(self, permission: str) -> int:
        permission_lower = permission.lower()
        for term, level in self._privilege_levels.items():
            if term != "default" and term in permission_lower:
                return level
        return self._privilege_levels.get("default", 1)

    def service_edge_weight(self, edge: ServiceIdentityEdge) -> float:
        mechanism = edge.trust_mechanism.value
        mechanism_weights = self._edge_config.get("mechanism_weights", {})
        mech_weight = mechanism_weights.get(mechanism) or mechanism_weights.get(
            "default"
        )

        # Higher risk score → smaller traversal weight (easier to exploit)
        base = max(0.1, 1.0 - min(max(edge.risk_score, 0.0), 1.0) * 0.7)

        if mech_weight is not None:
            base = (base + mech_weight) / 2

        if edge.exploitability.lower() == "high":
            base = min(base * 0.8, 1.0)

        return max(min(base, 1.0), 0.1)

    def service_edge_privilege(self, edge: ServiceIdentityEdge) -> int:
        permission = edge.metadata.get("permission") if edge.metadata else None
        if permission:
            level = self.privilege_level(str(permission))
            if level is not None:
                return level

        mapping = {"high": 3, "medium": 2, "low": 1}
        return mapping.get(
            edge.exploitability.lower(), self._privilege_levels.get("default", 1)
        )

    def service_edge_metadata(self, edge: ServiceIdentityEdge) -> dict[str, Any]:
        return {
            "trust_mechanism": edge.trust_mechanism.value,
            "provider_source": edge.provider_source,
            "provider_target": edge.provider_target,
            "allowed_repositories": edge.allowed_repositories,
            "allowed_branches": edge.allowed_branches,
            "risk_score": edge.risk_score,
            "exploitability": edge.exploitability,
            "conditions": edge.conditions,
            "permission": edge.metadata.get("permission", edge.trust_mechanism.value),
        }
