"""Utility helpers for normalizing evidence payloads."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from itertools import islice
from typing import Any, TypedDict

from .collections import coerce_mapping, coerce_mapping_sequence, coerce_str_sequence


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


class IdentityUserEvidence(TypedDict, total=False):
    """Evidence describing identity user security posture."""

    user_id: Any
    username: str | None
    login: str | None
    email: str | None
    user_principal_name: str | None
    display_name: str | None
    status: str | None
    account_type: str | None
    account_enabled: bool | None
    mfa_enrolled: bool | None
    two_factor_authentication: bool | None
    last_login: str | None
    created: str | None
    admin_roles: list[str]
    role_names: list[str]
    directory_roles: list[Mapping[str, Any]]
    groups: list[Any]
    applications: list[Any]
    risk_factors: list[str]
    profile: Mapping[str, Any]
    metadata: Mapping[str, Any]


def _coerce_str_list(values: Iterable[Any] | None) -> list[str]:
    if not values:
        return []
    return [value for value in values if isinstance(value, str) and value]


def _clip_generic_sequence(value: Any, limit: int) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value]
    if isinstance(value, Iterable):
        return list(islice(value, limit))
    return [value]


def build_identity_user_evidence(
    *,
    user_id: Any = None,
    username: str | None = None,
    login: str | None = None,
    email: str | None = None,
    user_principal_name: str | None = None,
    display_name: str | None = None,
    status: str | None = None,
    account_type: str | None = None,
    account_enabled: bool | None = None,
    mfa_enrolled: bool | None = None,
    two_factor_authentication: bool | None = None,
    last_login: str | None = None,
    created: str | None = None,
    admin_roles: Iterable[str] | None = None,
    role_names: Iterable[str] | None = None,
    directory_roles: Iterable[Mapping[str, Any]] | None = None,
    groups: Iterable[Any] | None = None,
    applications: Iterable[Any] | None = None,
    risk_factors: Iterable[str] | None = None,
    profile: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    extra: Mapping[str, Any] | None = None,
    limit: int = 10,
) -> IdentityUserEvidence:
    """Create standardized evidence payload for identity user risks.

    This helper should be used by all identity- and access-management oriented
    producers so that we consistently clamp large collections (groups,
    applications, directory roles), normalize string fields, and avoid manual
    slicing. Producers should prefer passing raw provider payloads—this helper
    will coerce them into safe, bounded structures and accept optional
    ``extra`` metadata for scenario-specific keys.
    """

    evidence: IdentityUserEvidence = {}

    if user_id is not None:
        evidence["user_id"] = user_id
    if username is not None:
        evidence["username"] = username
    if login is not None:
        evidence["login"] = login
    if email is not None:
        evidence["email"] = email
    if user_principal_name is not None:
        evidence["user_principal_name"] = user_principal_name
    if display_name is not None:
        evidence["display_name"] = display_name
    if status is not None:
        evidence["status"] = status
    if account_type is not None:
        evidence["account_type"] = account_type
    if account_enabled is not None:
        evidence["account_enabled"] = account_enabled
    if mfa_enrolled is not None:
        evidence["mfa_enrolled"] = mfa_enrolled
    if two_factor_authentication is not None:
        evidence["two_factor_authentication"] = two_factor_authentication
    if last_login is not None:
        evidence["last_login"] = last_login
    if created is not None:
        evidence["created"] = created

    admin_roles_list = _coerce_str_list(admin_roles)
    if admin_roles_list:
        evidence["admin_roles"] = admin_roles_list

    role_names_list = _coerce_str_list(role_names)
    if role_names_list:
        evidence["role_names"] = role_names_list

    dir_roles = list(coerce_mapping_sequence(directory_roles))
    if dir_roles:
        evidence["directory_roles"] = list(islice(dir_roles, limit))

    groups_clipped = _clip_generic_sequence(groups, limit)
    if groups_clipped:
        evidence["groups"] = groups_clipped

    apps_clipped = _clip_generic_sequence(applications, limit)
    if apps_clipped:
        evidence["applications"] = apps_clipped

    risk_list = _coerce_str_list(risk_factors)
    if risk_list:
        evidence["risk_factors"] = risk_list

    if profile:
        evidence["profile"] = compact_mapping(profile)

    if metadata:
        evidence["metadata"] = dict(metadata)

    if extra:
        evidence.update(extra)

    return evidence


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


class CiPipelineExposureEvidence(TypedDict, total=False):
    """Evidence describing CI/CD pipeline exposure risks."""

    project: str | None
    pipeline_id: str | None
    source_type: str | None
    repository: str | None
    auth_type: str | None
    auth_resource: str | None
    webhook_host: str | None
    webhook_present: bool | None
    filter_groups: list[Any]
    report_build_status: bool | None
    insecure_ssl: bool | None
    env_variables: list[Any]
    tokens_present: bool | None
    logs_enabled: bool | None
    metadata: Mapping[str, Any]


def build_ci_pipeline_exposure(
    *,
    project: str | None,
    source_type: str | None = None,
    repository: str | None = None,
    auth_type: str | None = None,
    auth_resource: str | None = None,
    webhook_host: str | None = None,
    webhook_present: bool | None = None,
    filter_groups: Iterable[Any] | None = None,
    report_build_status: bool | None = None,
    insecure_ssl: bool | None = None,
    env_variables: Iterable[Any] | None = None,
    tokens_present: bool | None = None,
    logs_enabled: bool | None = None,
    metadata: Mapping[str, Any] | None = None,
    extra: Mapping[str, Any] | None = None,
    limit: int = 10,
) -> CiPipelineExposureEvidence:
    """Create standardized evidence payload for CI/CD exposures.

    Use this helper for build-system findings (e.g., CodeBuild, GitHub Actions)
    to capture consistent metadata about source repositories, authentication
    methods, webhook state, and environment variables. Lists such as
    ``filter_groups`` and ``env_variables`` are automatically clipped to avoid
    large payloads while preserving type fidelity.
    """

    evidence: CiPipelineExposureEvidence = {
        "project": project,
    }

    if source_type is not None:
        evidence["source_type"] = source_type
    if repository is not None:
        evidence["repository"] = repository
    if auth_type is not None:
        evidence["auth_type"] = auth_type
    if auth_resource is not None:
        evidence["auth_resource"] = auth_resource
    if webhook_host is not None:
        evidence["webhook_host"] = webhook_host
    if webhook_present is not None:
        evidence["webhook_present"] = webhook_present
    if report_build_status is not None:
        evidence["report_build_status"] = report_build_status
    if insecure_ssl is not None:
        evidence["insecure_ssl"] = insecure_ssl
    if tokens_present is not None:
        evidence["tokens_present"] = tokens_present
    if logs_enabled is not None:
        evidence["logs_enabled"] = logs_enabled

    filter_list = _clip_generic_sequence(filter_groups, limit)
    if filter_list:
        evidence["filter_groups"] = filter_list

    env_list = _clip_generic_sequence(env_variables, limit)
    if env_list:
        evidence["env_variables"] = env_list

    if metadata:
        evidence["metadata"] = dict(metadata)

    if extra:
        evidence.update(extra)

    return evidence


class NetworkExposureDetail(TypedDict, total=False):
    """Detail entry describing a specific network exposure."""

    type: str | None
    hosts: list[str]
    ports: list[int]
    load_balancer: list[Any]
    ip: str | None
    public: bool | None
    description: str | None
    metadata: Mapping[str, Any]


class NetworkExposureEvidence(TypedDict, total=False):
    """Evidence describing network exposure and namespace posture."""

    namespace: str | None
    service_type: str | None
    ingress_class: str | None
    annotations: Mapping[str, Any] | None
    namespace_network_posture: Mapping[str, Any] | None
    exposures: list[NetworkExposureDetail]


def _summarize_exposure(entry: Mapping[str, Any]) -> NetworkExposureDetail:
    result: NetworkExposureDetail = {}
    if "type" in entry:
        result["type"] = entry.get("type")
    hosts = entry.get("hosts")
    if isinstance(hosts, Iterable) and not isinstance(hosts, (str, bytes)):
        result["hosts"] = list(islice(hosts, 20))
    ports = entry.get("ports")
    if isinstance(ports, Iterable) and not isinstance(ports, (str, bytes)):
        result["ports"] = [
            port for port in islice(ports, 20) if isinstance(port, int)
        ]
    if "port" in entry and isinstance(entry.get("port"), int):
        result["port"] = entry.get("port")
    if "service_port" in entry and isinstance(entry.get("service_port"), int):
        result["service_port"] = entry.get("service_port")
    load_balancer = entry.get("load_balancer")
    if load_balancer is not None:
        result["load_balancer"] = _clip_generic_sequence(load_balancer, 10)
    ip_value = entry.get("ip")
    if isinstance(ip_value, str):
        result["ip"] = ip_value
    if "public" in entry:
        result["public"] = bool(entry.get("public"))
    description = entry.get("description")
    if isinstance(description, str):
        result["description"] = description
    metadata = entry.get("metadata")
    if isinstance(metadata, Mapping):
        result["metadata"] = dict(metadata)
    return result


def build_network_exposure_evidence(
    *,
    namespace: str | None,
    exposures: Iterable[Mapping[str, Any]],
    annotations: Mapping[str, Any] | None = None,
    namespace_network_posture: Mapping[str, Any] | None = None,
    service_type: str | None = None,
    ingress_class: str | None = None,
    extra: Mapping[str, Any] | None = None,
    limit: int = 10,
) -> NetworkExposureEvidence:
    """Create evidence payload for network exposure findings.

    Kubernetes producers should route exposure maps through this helper to keep
    namespace posture data, annotations, and exposure details normalized. The
    builder trims large exposure lists, preserves key fields like ``port`` and
    ``ip``, and accepts ``extra`` metadata for resource-specific attributes
    (e.g., provider IDs or service flags).
    """

    exposure_entries = [
        _summarize_exposure(entry)
        for entry in islice(exposures, limit)
    ]

    evidence: NetworkExposureEvidence = {
        "namespace": namespace,
        "exposures": exposure_entries,
    }

    if service_type is not None:
        evidence["service_type"] = service_type
    if ingress_class is not None:
        evidence["ingress_class"] = ingress_class
    if annotations:
        evidence["annotations"] = annotations
    if namespace_network_posture:
        evidence["namespace_network_posture"] = namespace_network_posture
    if extra:
        evidence.update(extra)

    return evidence


class SecurityGroupRuleSummary(TypedDict, total=False):
    """Summary of an individual security group rule."""

    direction: str | None
    protocol: str | None
    from_port: int | None
    to_port: int | None
    port: int | None
    cidr: str | None
    cidrs: list[str]
    description: str | None
    service: str | None
    metadata: Mapping[str, Any]


class SecurityGroupExposureEvidence(TypedDict, total=False):
    """Evidence describing security group exposure posture."""

    group_id: str | None
    group_name: str | None
    vpc_id: str | None
    attached_resources: list[Any]
    public_rules: list[SecurityGroupRuleSummary]
    total_rules: int | None
    metadata: Mapping[str, Any]


def build_security_group_exposure(
    *,
    group_id: str | None,
    group_name: str | None = None,
    vpc_id: str | None = None,
    attached_resources: Iterable[Any] | None = None,
    public_rules: Iterable[Mapping[str, Any]] | None = None,
    total_rules: int | None = None,
    metadata: Mapping[str, Any] | None = None,
    limit: int = 20,
) -> SecurityGroupExposureEvidence:
    """Create evidence payload representing security group exposures."""

    def _summarize_rule(rule: Mapping[str, Any]) -> SecurityGroupRuleSummary:
        summary: SecurityGroupRuleSummary = {}
        direction = rule.get("direction")
        if isinstance(direction, str):
            summary["direction"] = direction
        protocol = rule.get("protocol")
        if isinstance(protocol, str):
            summary["protocol"] = protocol
        for key in ("from_port", "to_port"):
            value = rule.get(key)
            if isinstance(value, int):
                summary[key] = value
        cidr = rule.get("cidr") or rule.get("cidr_block")
        if isinstance(cidr, str):
            summary["cidr"] = cidr
        cidrs = rule.get("cidrs")
        if isinstance(cidrs, Iterable):
            summary["cidrs"] = list(islice(cidrs, limit))
        port = rule.get("port")
        if isinstance(port, int):
            summary["port"] = port
        service = rule.get("service")
        if isinstance(service, str):
            summary["service"] = service
        description = rule.get("description")
        if isinstance(description, str):
            summary["description"] = description
        metadata = rule.get("metadata")
        if isinstance(metadata, Mapping):
            summary["metadata"] = dict(metadata)
        return summary

    evidence: SecurityGroupExposureEvidence = {
        "group_id": group_id,
    }

    if group_name is not None:
        evidence["group_name"] = group_name
    if vpc_id is not None:
        evidence["vpc_id"] = vpc_id
    if total_rules is not None:
        evidence["total_rules"] = total_rules

    if attached_resources is not None:
        evidence["attached_resources"] = _clip_generic_sequence(
            attached_resources, limit
        )

    if public_rules is not None:
        summarized = [
            _summarize_rule(rule) for rule in islice(public_rules, limit)
        ]
        evidence["public_rules"] = summarized

    if metadata:
        evidence["metadata"] = dict(metadata)

    return evidence


class WorkflowPermissionEvidence(TypedDict, total=False):
    """Evidence describing GitHub workflow permission posture."""

    repository: str | None
    organization: str | None
    default_permissions: Mapping[str, Any] | None
    workflow_access: Mapping[str, Any] | None
    pinned_workflows: list[Any]
    risk_factors: list[str]


def build_workflow_permission_evidence(
    *,
    repository: str | None = None,
    organization: str | None = None,
    default_permissions: Mapping[str, Any] | None = None,
    workflow_access: Mapping[str, Any] | None = None,
    pinned_workflows: Iterable[Any] | None = None,
    risk_factors: Iterable[str] | None = None,
    limit: int = 20,
) -> WorkflowPermissionEvidence:
    """Create standardized evidence for workflow permission findings."""

    evidence: WorkflowPermissionEvidence = {}
    if repository is not None:
        evidence["repository"] = repository
    if organization is not None:
        evidence["organization"] = organization
    if default_permissions:
        default_permissions_dict = dict(default_permissions)
        evidence["default_permissions"] = default_permissions_dict
        default_workflow = default_permissions_dict.get(
            "default_workflow_permissions"
        )
        if default_workflow is not None:
            evidence["default_workflow_permissions"] = default_workflow
    if workflow_access:
        workflow_access_dict = dict(workflow_access)
        evidence["workflow_access"] = workflow_access_dict
        allowed_actions = workflow_access_dict.get("allowed_actions")
        if allowed_actions is not None:
            evidence["allowed_actions"] = allowed_actions
        if "can_approve_pull_request_reviews" in workflow_access_dict:
            evidence["can_approve_pull_request_reviews"] = workflow_access_dict[
                "can_approve_pull_request_reviews"
            ]
    if pinned_workflows is not None:
        evidence["pinned_workflows"] = _clip_generic_sequence(
            pinned_workflows, limit
        )
    risk_list = _coerce_str_list(risk_factors)
    if risk_list:
        evidence["risk_factors"] = risk_list
    return evidence


class TelemetryIncidentEvidence(TypedDict, total=False):
    """Evidence describing telemetry-detected incidents or secrets."""

    repository: str | None
    file_path: str | None
    line_number: int | None
    secret_type: str | None
    secret_family: str | None
    detector: str | None
    validation: Mapping[str, Any]
    commit_sha: str | None
    graph_controls: list[Any]
    metadata: Mapping[str, Any]


def build_telemetry_incident_evidence(
    *,
    repository: str | None,
    file_path: str | None,
    line_number: int | None,
    secret_type: str | None,
    secret_family: str | None,
    detector: str | None,
    validation: Mapping[str, Any],
    commit_sha: str | None = None,
    graph_controls: Iterable[Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    limit: int = 20,
) -> TelemetryIncidentEvidence:
    """Create evidence payload for secrets or telemetry incidents."""

    evidence: TelemetryIncidentEvidence = {
        "repository": repository,
        "file_path": file_path,
        "line_number": line_number,
        "secret_type": secret_type,
        "secret_family": secret_family,
        "detector": detector,
        "validation": dict(validation),
    }

    if commit_sha is not None:
        evidence["commit_sha"] = commit_sha

    if graph_controls is not None:
        evidence["graph_controls"] = _clip_generic_sequence(
            graph_controls, limit
        )

    if metadata:
        evidence["metadata"] = dict(metadata)

    return evidence
