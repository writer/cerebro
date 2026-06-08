from typing import Any, Dict, Optional, TypedDict

from .client import Client


SUPPORTED_CLAIM_TYPES = frozenset(("existence", "attribute", "relation", "classification"))
SUPPORTED_STATUSES = frozenset(("asserted", "retracted", "refuted", "superseded"))
PANOPTICON_RUNTIME_CONFIG = {"source": "panopticon", "mode": "push_claims"}

CANONICAL_CLAIM_FIELDS = frozenset(
    (
        "id",
        "subject_ref",
        "subject_urn",
        "predicate",
        "object_ref",
        "object_urn",
        "object_value",
        "claim_type",
        "status",
        "source_event_id",
        "observed_at",
        "valid_from",
        "valid_to",
        "attributes",
    )
)


class PanopticonEntityRef(TypedDict, total=False):
    urn: str
    entity_type: str
    label: str


class PanopticonPushClaim(TypedDict, total=False):
    id: str
    subject_ref: PanopticonEntityRef
    subject_urn: str
    predicate: str
    object_ref: PanopticonEntityRef
    object_urn: str
    object_value: str
    claim_type: str
    status: str
    source_event_id: str
    observed_at: str
    valid_from: str
    valid_to: str
    attributes: Dict[str, str]


class OnboardPanopticonPushClaimsResult(TypedDict):
    write_result: Dict[str, Any]
    submitted_claims: list[Dict[str, Any]]


def build_panopticon_push_claims(claims: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    if not isinstance(claims, list):
        raise ValueError("claims must be a list")
    normalized: list[Dict[str, Any]] = []
    for index, raw in enumerate(claims):
        if not isinstance(raw, dict):
            raise ValueError(f"claims[{index}] must be an object")
        normalized.append(_normalize_claim(raw, f"claims[{index}]"))
    return normalized


def onboard_panopticon_push_claims(
    base_url: str,
    tenant_id: str,
    runtime_id: str,
    claims: list[Dict[str, Any]],
    api_key: Optional[str] = None,
    runtime_config: Optional[Dict[str, str]] = None,
    replace_existing: bool = True,
) -> OnboardPanopticonPushClaimsResult:
    submitted_claims = build_panopticon_push_claims(claims)
    client = Client(base_url=base_url, api_key=api_key or None)
    integration = client.integration(runtime_id=runtime_id, tenant_id=tenant_id, integration="panopticon")
    integration.ensure_runtime({**PANOPTICON_RUNTIME_CONFIG, **string_map(runtime_config or {}, "runtime_config")})
    write_result = integration.write_claims(submitted_claims, {"replace_existing": replace_existing})
    return {
        "write_result": write_result,
        "submitted_claims": submitted_claims,
    }


def string_map(value: Dict[str, Any], name: str) -> Dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    normalized: Dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError(f"{name} keys must be non-empty strings")
        if not isinstance(item, str):
            raise ValueError(f"{name}.{key} must be a string")
        stripped = item.strip()
        if stripped:
            normalized[key.strip()] = stripped
    return normalized


def _normalize_claim(raw: Dict[str, Any], path: str) -> Dict[str, Any]:
    unknown = sorted(set(raw) - CANONICAL_CLAIM_FIELDS)
    if unknown:
        raise ValueError(f"{path} unsupported field {unknown[0]!r}; use canonical snake_case claim fields")

    subject_urn = require_string(raw.get("subject_urn"), f"{path}.subject_urn")
    predicate = require_string(raw.get("predicate"), f"{path}.predicate")
    claim_type = require_string(raw.get("claim_type"), f"{path}.claim_type")
    if claim_type not in SUPPORTED_CLAIM_TYPES:
        raise ValueError(f"{path}.claim_type has unsupported claim_type {claim_type!r}")

    normalized: Dict[str, Any] = {
        "subject_urn": subject_urn,
        "predicate": predicate,
        "claim_type": claim_type,
    }
    copy_optional_string(raw, normalized, "id", path)
    copy_optional_ref(raw, normalized, "subject_ref", path)
    copy_optional_ref(raw, normalized, "object_ref", path)
    copy_optional_string(raw, normalized, "object_urn", path)
    copy_optional_string(raw, normalized, "object_value", path)
    copy_optional_string(raw, normalized, "source_event_id", path)
    copy_optional_string(raw, normalized, "observed_at", path)
    copy_optional_string(raw, normalized, "valid_from", path)
    copy_optional_string(raw, normalized, "valid_to", path)

    status = optional_string(raw.get("status"), f"{path}.status") or "asserted"
    if status not in SUPPORTED_STATUSES:
        raise ValueError(f"{path}.status must be one of {sorted(SUPPORTED_STATUSES)}")
    normalized["status"] = status

    if "attributes" in raw and raw.get("attributes") is not None:
        attributes = string_map(raw["attributes"], f"{path}.attributes")
        if attributes:
            normalized["attributes"] = attributes

    if claim_type in ("attribute", "classification") and not normalized.get("object_value"):
        raise ValueError(f"{path}.object_value is required when claim_type={claim_type!r}")
    if claim_type == "relation" and not normalized.get("object_urn"):
        raise ValueError(f"{path}.object_urn is required when claim_type='relation'")

    ordered: Dict[str, Any] = {}
    for key in (
        "id",
        "subject_ref",
        "subject_urn",
        "predicate",
        "object_ref",
        "object_urn",
        "object_value",
        "claim_type",
        "status",
        "source_event_id",
        "observed_at",
        "valid_from",
        "valid_to",
        "attributes",
    ):
        if key in normalized:
            ordered[key] = normalized[key]
    return ordered


def copy_optional_string(raw: Dict[str, Any], normalized: Dict[str, Any], key: str, path: str) -> None:
    value = optional_string(raw.get(key), f"{path}.{key}")
    if value is not None:
        normalized[key] = value


def copy_optional_ref(raw: Dict[str, Any], normalized: Dict[str, Any], key: str, path: str) -> None:
    if key not in raw or raw.get(key) is None:
        return
    value = raw[key]
    if not isinstance(value, dict):
        raise ValueError(f"{path}.{key} must be an object")
    unknown = sorted(set(value) - {"urn", "entity_type", "label"})
    if unknown:
        raise ValueError(f"{path}.{key} unsupported field {unknown[0]!r}")
    ref: Dict[str, str] = {}
    for ref_key in ("urn", "entity_type", "label"):
        ref_value = optional_string(value.get(ref_key), f"{path}.{key}.{ref_key}")
        if ref_value is not None:
            ref[ref_key] = ref_value
    if not ref.get("urn"):
        raise ValueError(f"{path}.{key}.urn is required")
    normalized[key] = ref


def require_string(value: Any, name: str) -> str:
    normalized = optional_string(value, name)
    if normalized is None:
        raise ValueError(f"{name} is required")
    return normalized


def optional_string(value: Any, name: str) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    normalized = value.strip()
    return normalized or None


__all__ = [
    "SUPPORTED_CLAIM_TYPES",
    "PanopticonEntityRef",
    "PanopticonPushClaim",
    "OnboardPanopticonPushClaimsResult",
    "build_panopticon_push_claims",
    "onboard_panopticon_push_claims",
]
