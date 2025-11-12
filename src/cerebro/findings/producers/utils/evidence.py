"""Utility helpers for normalizing evidence payloads."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from itertools import islice
from typing import Any, TypedDict

from .collections import coerce_mapping, coerce_str_sequence


def clip_sequence(values: Iterable[Any] | None, limit: int = 10) -> list[Any]:
    """Return at most ``limit`` items from ``values`` as a list."""

    if not values or limit <= 0:
        return []

    if isinstance(values, Sequence):
        return list(values[: limit])  # type: ignore[index]

    return list(islice(values, limit))


def compact_mapping(mapping: Mapping[str, Any] | None) -> dict[str, Any]:
    """Remove keys with ``None`` values from a mapping."""

    if not mapping:
        return {}

    return {key: value for key, value in mapping.items() if value is not None}


class SecretArtifactSummary(TypedDict, total=False):
    """Summary of a potentially sensitive object detected in storage."""

    name: str | None
    key: str | None
    content_type: str | None
    size_bytes: int | None


class StorageSecretExposureEvidence(TypedDict, total=False):
    """Structured evidence describing leaked artifacts in storage."""

    storage_id: str
    bucket: str
    container: str
    account_name: str
    region: str | None
    location: str | None
    matched_objects: list[SecretArtifactSummary]
    sample_size: int | None
    object_sample_size: int | None
    public_access: Mapping[str, Any] | None
    access_context: Mapping[str, Any] | None


def _coerce_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def build_storage_secret_evidence(
    *,
    storage_id: str,
    artifacts: Iterable[Mapping[str, Any]] | Sequence[Mapping[str, Any]],
    sample_size: int | None = None,
    region: str | None = None,
    location: str | None = None,
    public_access: Mapping[str, Any] | None = None,
    access_context: Mapping[str, Any] | None = None,
    extra: Mapping[str, Any] | None = None,
    limit: int = 10,
) -> StorageSecretExposureEvidence:
    """Create standardized evidence payload for storage secret exposures."""

    entries: list[SecretArtifactSummary] = []
    for artifact in clip_sequence(artifacts, limit=limit):
        summary: SecretArtifactSummary = {}

        name = artifact.get("name") or artifact.get("key")
        if name is not None:
            summary["name"] = _coerce_str(name)

        key = artifact.get("key")
        if key is not None:
            summary["key"] = _coerce_str(key)

        content_type = artifact.get("content_type") or artifact.get("mimeType")
        if content_type is not None:
            summary["content_type"] = _coerce_str(content_type)

        size_value = artifact.get("size") or artifact.get("size_bytes")
        size_bytes = _coerce_int(size_value)
        if size_bytes is not None:
            summary["size_bytes"] = size_bytes

        entries.append(summary)

    evidence: StorageSecretExposureEvidence = {
        "storage_id": storage_id,
        "matched_objects": entries,
    }

    if region is not None:
        evidence["region"] = region

    if location is not None:
        evidence["location"] = location

    if sample_size is not None:
        evidence["sample_size"] = sample_size
        evidence.setdefault("object_sample_size", sample_size)

    if public_access is not None:
        evidence["public_access"] = public_access

    if access_context is not None:
        evidence["access_context"] = access_context

    if extra:
        evidence.update(extra)

    return evidence


class RunnerMetadata(TypedDict, total=False):
    """Essential metadata describing a runner instance."""

    id: Any
    name: str | None
    os: str | None
    labels: list[Any] | None


class RunnerGroupExposureEvidence(TypedDict, total=False):
    """Evidence payload for runner groups exposed to public repositories."""

    runner: RunnerMetadata
    runner_group: Mapping[str, Any]
    exposed_repositories: list[Mapping[str, Any]]


class RunnerHostExposureEvidence(TypedDict, total=False):
    """Evidence payload capturing host-level runner exposure."""

    runner: RunnerMetadata
    host: Mapping[str, Any]


def _extract_runner_metadata(source: Mapping[str, Any]) -> RunnerMetadata:
    return {
        "id": source.get("id"),
        "name": _coerce_str(source.get("name")),
        "os": _coerce_str(source.get("os")),
        "labels": list(source.get("labels", []) or []),
    }


def build_runner_group_exposure(
    *,
    runner: Mapping[str, Any],
    runner_group: Mapping[str, Any],
    exposed_repositories: Iterable[Mapping[str, Any]],
    limit: int = 10,
) -> RunnerGroupExposureEvidence:
    """Create standardized evidence for runner group exposure."""

    repositories = [dict(repo) for repo in clip_sequence(exposed_repositories, limit)]

    return {
        "runner": _extract_runner_metadata(runner),
        "runner_group": dict(runner_group),
        "exposed_repositories": repositories,
    }


def build_runner_host_exposure(
    *,
    runner: Mapping[str, Any],
    host: Mapping[str, Any],
    public_ips: Sequence[str],
    listening_ports: Sequence[int],
) -> RunnerHostExposureEvidence:
    """Create standardized evidence for runner host network exposure."""

    host_payload = {
        "host_id": host.get("host_id"),
        "hostname": host.get("hostname"),
        "public_ips": list(public_ips),
        "listening_ports": list(listening_ports),
    }

    return {
        "runner": _extract_runner_metadata(runner),
        "host": host_payload,
    }


class ExternalUserAccess(TypedDict, total=False):
    """Summary of an external user's permissions."""

    email: str | None
    display_name: str | None
    roles: list[str]


class ExternalSharingEvidence(TypedDict, total=False):
    """Evidence describing external sharing configuration for SharePoint."""

    site_name: str | None
    site_url: str | None
    site_id: str | None
    sharing_capability: str | None
    external_sharing_enabled: bool
    external_users_count: int
    external_users: list[ExternalUserAccess]


def _summarize_external_permission(
    permission: Mapping[str, Any],
) -> ExternalUserAccess:
    granted = coerce_mapping(permission.get("grantedToV2"))
    user = coerce_mapping(granted.get("user")) if granted else None
    email = user.get("email") if isinstance(user, Mapping) else None
    display_name = user.get("displayName") if isinstance(user, Mapping) else None
    roles = list(coerce_str_sequence(permission.get("roles")))
    return {
        "email": email,
        "display_name": display_name,
        "roles": roles,
    }


def build_external_sharing_evidence(
    *,
    site_name: str | None,
    site_url: str | None,
    site_id: str | None,
    sharing_capability: str | None,
    external_sharing_enabled: bool,
    external_permissions: Iterable[Mapping[str, Any]],
    limit: int = 10,
) -> ExternalSharingEvidence:
    """Create standardized evidence payload for SharePoint external users."""

    permissions = list(external_permissions)
    summarized = [
        _summarize_external_permission(permission)
        for permission in clip_sequence(permissions, limit=limit)
    ]

    evidence: ExternalSharingEvidence = {
        "site_name": site_name,
        "site_url": site_url,
        "site_id": site_id,
        "sharing_capability": sharing_capability,
        "external_sharing_enabled": external_sharing_enabled,
        "external_users_count": len(permissions),
        "external_users": summarized,
    }

    return evidence


class AnonymousLinkSummary(TypedDict, total=False):
    """Summary of an anonymous sharing link."""

    scope: str | None
    type: str | None
    roles: list[str]


class SharePointAnonymousLinkEvidence(TypedDict, total=False):
    """Evidence describing anonymous link exposure for SharePoint sites."""

    site_url: str | None
    sharing_capability: str | None
    anonymous_links: list[AnonymousLinkSummary]


def _summarize_anonymous_link(permission: Mapping[str, Any]) -> AnonymousLinkSummary:
    link = coerce_mapping(permission.get("link")) or {}
    roles = list(coerce_str_sequence(permission.get("roles")))
    return {
        "scope": link.get("scope"),
        "type": link.get("type"),
        "roles": roles,
    }


def build_sharepoint_anonymous_link_evidence(
    *,
    site_url: str | None,
    sharing_capability: str | None,
    permissions: Iterable[Mapping[str, Any]],
    limit: int = 5,
) -> SharePointAnonymousLinkEvidence:
    """Create standardized evidence payload for SharePoint anonymous links."""

    summaries = [
        _summarize_anonymous_link(permission)
        for permission in clip_sequence(permissions, limit=limit)
    ]

    return {
        "site_url": site_url,
        "sharing_capability": sharing_capability,
        "anonymous_links": summaries,
    }
