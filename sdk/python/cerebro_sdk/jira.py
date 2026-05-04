from typing import Any, Dict, Optional, TypedDict

from .client import Client, IntegrationClient


class JiraAdminPosture(TypedDict, total=False):
    email: str
    display_name: str
    role: str


class JiraProjectPosture(TypedDict, total=False):
    key: str
    name: str
    classification: str
    issue_level_security_enabled: bool
    anonymous_browse_enabled: bool
    service_desk_public_portal_enabled: bool


class JiraMarketplaceAppPosture(TypedDict, total=False):
    key: str
    name: str
    approved_by_security: bool
    scopes: list[str]


class JiraWorkspacePosture(TypedDict, total=False):
    workspace_key: str
    workspace_name: str
    event_id: str
    sso_enforced: bool
    mfa_required_for_admins: bool
    atlassian_guard_enabled: bool
    audit_log_export_enabled: bool
    api_token_expiration_enforced: bool
    public_signup_enabled: bool
    anonymous_access_enabled: bool
    approved_marketplace_apps_only: bool
    admins: list[JiraAdminPosture]
    projects: list[JiraProjectPosture]
    apps: list[JiraMarketplaceAppPosture]


class JiraWorkspaceGraphLayering(TypedDict):
    workspace: Dict[str, Any]
    projects: Dict[str, Dict[str, Any]]
    summary: Dict[str, Any]


class JiraPostureFinding(TypedDict, total=False):
    id: str
    severity: str
    title: str
    summary: str
    resource_urns: list[str]
    attributes: Dict[str, str]


class OnboardJiraWorkspacePostureResult(TypedDict):
    workspace_urn: str
    write_result: Dict[str, Any]
    submitted_claims: list[Dict[str, Any]]
    persisted_claims: list[Dict[str, Any]]
    graph_layering: JiraWorkspaceGraphLayering
    graph_summary: Dict[str, Any]
    posture_findings: list[JiraPostureFinding]


def build_jira_workspace_claims(
    integration: IntegrationClient,
    posture: JiraWorkspacePosture,
) -> list[Dict[str, Any]]:
    posture = object_value(posture)
    workspace_key = require_value(posture.get("workspace_key"), "workspace_key")
    workspace_name = optional_string(posture.get("workspace_name")) or workspace_key
    workspace_ref = integration.ref("workspace", workspace_key, workspace_name)
    source_event_id = optional_string(posture.get("event_id"))
    shared_options: Dict[str, Any] = {"source_event_id": source_event_id} if source_event_id else {}
    admins = object_list(posture.get("admins"), "admins")
    projects = object_list(posture.get("projects"), "projects")
    apps = object_list(posture.get("apps"), "apps")

    claims = [
        integration.exists(workspace_ref, **shared_options),
        integration.attr(workspace_ref, "platform", "jira", **shared_options),
        integration.attr(workspace_ref, "vendor", "atlassian", **shared_options),
        integration.attr(workspace_ref, "sso_enforced", bool_value(posture.get("sso_enforced"), True), **shared_options),
        integration.attr(
            workspace_ref,
            "mfa_required_for_admins",
            bool_value(posture.get("mfa_required_for_admins"), True),
            **shared_options,
        ),
        integration.attr(
            workspace_ref,
            "atlassian_guard_enabled",
            bool_value(posture.get("atlassian_guard_enabled"), True),
            **shared_options,
        ),
        integration.attr(
            workspace_ref,
            "audit_log_export_enabled",
            bool_value(posture.get("audit_log_export_enabled"), True),
            **shared_options,
        ),
        integration.attr(
            workspace_ref,
            "api_token_expiration_enforced",
            bool_value(posture.get("api_token_expiration_enforced"), True),
            **shared_options,
        ),
        integration.attr(
            workspace_ref,
            "public_signup_enabled",
            bool_value(posture.get("public_signup_enabled"), False),
            **shared_options,
        ),
        integration.attr(
            workspace_ref,
            "anonymous_access_enabled",
            bool_value(posture.get("anonymous_access_enabled"), False),
            **shared_options,
        ),
        integration.attr(
            workspace_ref,
            "approved_marketplace_apps_only",
            bool_value(posture.get("approved_marketplace_apps_only"), True),
            **shared_options,
        ),
        integration.attr(
            workspace_ref,
            "admin_count",
            str(len({require_value(admin.get("email"), "admins[].email").casefold() for admin in admins})),
            **shared_options,
        ),
        integration.attr(workspace_ref, "project_count", str(len(projects)), **shared_options),
        integration.attr(workspace_ref, "installed_app_count", str(len(apps)), **shared_options),
    ]

    for admin in admins:
        email = require_value(admin.get("email"), "admins[].email").casefold()
        label = optional_string(admin.get("display_name")) or email
        role = optional_string(admin.get("role")) or "site_admin"
        admin_ref = integration.ref("user", email, label)
        claims.append(integration.exists(admin_ref, **shared_options))
        claims.append(integration.rel(admin_ref, "administers", workspace_ref, **shared_options))
        claims.append(integration.attr(admin_ref, "role", role, **shared_options))

    for project in projects:
        key = require_value(project.get("key"), "projects[].key")
        name = optional_string(project.get("name")) or key
        project_ref = integration.ref("project", key, name)
        claims.append(integration.exists(project_ref, **shared_options))
        claims.append(integration.rel(project_ref, "belongs_to", workspace_ref, **shared_options))
        claims.append(
            integration.attr(
                project_ref,
                "classification",
                optional_string(project.get("classification")) or "internal",
                **shared_options,
            )
        )
        claims.append(
            integration.attr(
                project_ref,
                "issue_level_security_enabled",
                bool_value(project.get("issue_level_security_enabled"), True),
                **shared_options,
            )
        )
        claims.append(
            integration.attr(
                project_ref,
                "anonymous_browse_enabled",
                bool_value(project.get("anonymous_browse_enabled"), False),
                **shared_options,
            )
        )
        claims.append(
            integration.attr(
                project_ref,
                "service_desk_public_portal_enabled",
                bool_value(project.get("service_desk_public_portal_enabled"), False),
                **shared_options,
            )
        )

    for app in apps:
        key = require_value(app.get("key"), "apps[].key")
        name = optional_string(app.get("name")) or key
        app_ref = integration.ref("app", key, name)
        claims.append(integration.exists(app_ref, **shared_options))
        claims.append(integration.rel(app_ref, "installed_on", workspace_ref, **shared_options))
        claims.append(
            integration.attr(
                app_ref,
                "approved_by_security",
                bool_value(app.get("approved_by_security"), True),
                **shared_options,
            )
        )
        scopes = [optional_string(scope) for scope in list_value(app.get("scopes"))]
        normalized_scopes = [scope for scope in scopes if scope]
        if normalized_scopes:
            claims.append(integration.attr(app_ref, "scopes", ",".join(normalized_scopes), **shared_options))

    return claims


def load_jira_workspace_graph_layering(
    integration: IntegrationClient,
    posture: JiraWorkspacePosture,
) -> JiraWorkspaceGraphLayering:
    posture = object_value(posture)
    workspace_key = require_value(posture.get("workspace_key"), "workspace_key")
    workspace_name = optional_string(posture.get("workspace_name")) or workspace_key
    workspace_ref = integration.ref("workspace", workspace_key, workspace_name)
    project_refs = []
    project_keys = []
    for project in object_list(posture.get("projects"), "projects"):
        project_key = require_value(project.get("key"), "projects[].key")
        project_name = optional_string(project.get("name")) or project_key
        project_refs.append(integration.ref("project", project_key, project_name))
        project_keys.append(project_key)
    workspace_graph = integration.graph_layering([workspace_ref], limit=50)
    project_layering = integration.graph_layering(project_refs, limit=12)
    combined_layering = dict(workspace_graph)
    combined_layering.update(project_layering)
    project_graphs: Dict[str, Dict[str, Any]] = {}
    for project_key, project_ref in zip(project_keys, project_refs):
        project_graphs[project_key] = project_layering.get(
            project_ref["urn"],
            {"root_urn": project_ref["urn"], "error": "missing graph response"},
        )
    return {
        "workspace": workspace_graph.get(
            workspace_ref["urn"],
            {"root_urn": workspace_ref["urn"], "error": "missing graph response"},
        ),
        "projects": project_graphs,
        "summary": integration.graph_summary(combined_layering),
    }


def build_jira_posture_findings(
    integration: IntegrationClient,
    posture: JiraWorkspacePosture,
    graph_summary: Dict[str, Any],
) -> list[JiraPostureFinding]:
    posture = object_value(posture)
    findings: list[JiraPostureFinding] = []
    workspace_key = require_value(posture.get("workspace_key"), "workspace_key")
    workspace_name = optional_string(posture.get("workspace_name")) or workspace_key
    workspace_ref = integration.ref("workspace", workspace_key, workspace_name)

    if bool_value(posture.get("public_signup_enabled"), False) == "true":
        findings.append(
            finding(
                "jira_workspace_public_signup_enabled",
                "HIGH",
                "Jira workspace allows self-service signup",
                f"{workspace_name} allows self-service signup, which increases exposure to unmanaged identities.",
                [workspace_ref["urn"]],
            )
        )
    if bool_value(posture.get("anonymous_access_enabled"), False) == "true":
        findings.append(
            finding(
                "jira_workspace_anonymous_access_enabled",
                "HIGH",
                "Jira workspace permits anonymous access",
                f"{workspace_name} exposes content to unauthenticated users.",
                [workspace_ref["urn"]],
            )
        )
    if bool_value(posture.get("approved_marketplace_apps_only"), True) == "false":
        findings.append(
            finding(
                "jira_workspace_marketplace_policy_open",
                "MEDIUM",
                "Jira workspace does not restrict marketplace apps",
                f"{workspace_name} allows marketplace apps outside the approved set.",
                [workspace_ref["urn"]],
            )
        )

    relation_counts = graph_summary.get("relation_counts_by_type", {})
    if not isinstance(relation_counts, dict):
        relation_counts = {}
    posture_admin_emails = {
        email.casefold()
        for admin in object_list(posture.get("admins"), "admins")
        if (email := optional_string(admin.get("email")))
    }
    posture_admin_count = len(posture_admin_emails)
    admin_count = max(int(relation_counts.get("administers", 0)), posture_admin_count)
    if admin_count > 5:
        findings.append(
            finding(
                "jira_workspace_admin_sprawl",
                "MEDIUM",
                "Jira workspace has elevated admin sprawl",
                f"{workspace_name} has {admin_count} admin relationships in the graph neighborhood.",
                [workspace_ref["urn"]],
                {"admin_count": str(admin_count)},
            )
        )

    for project in object_list(posture.get("projects"), "projects"):
        project_key = require_value(project.get("key"), "projects[].key")
        project_name = optional_string(project.get("name")) or project_key
        project_ref = integration.ref("project", project_key, project_name)
        classification = optional_string(project.get("classification")) or "internal"
        if classification == "restricted" and bool_value(project.get("issue_level_security_enabled"), True) == "false":
            findings.append(
                finding(
                    f"jira_project_{project_key.lower()}_restricted_issue_security_disabled",
                    "HIGH",
                    "Restricted Jira project lacks issue-level security",
                    f"{project_name} is marked restricted but issue-level security is disabled.",
                    [project_ref["urn"], workspace_ref["urn"]],
                )
            )
        if bool_value(project.get("anonymous_browse_enabled"), False) == "true":
            findings.append(
                finding(
                    f"jira_project_{project_key.lower()}_anonymous_browse_enabled",
                    "HIGH",
                    "Jira project allows anonymous browsing",
                    f"{project_name} allows anonymous issue browsing.",
                    [project_ref["urn"], workspace_ref["urn"]],
                )
            )
        if bool_value(project.get("service_desk_public_portal_enabled"), False) == "true":
            findings.append(
                finding(
                    f"jira_project_{project_key.lower()}_public_portal_enabled",
                    "HIGH" if classification == "restricted" else "MEDIUM",
                    "Jira project exposes a public service desk portal",
                    f"{project_name} exposes a public portal for {classification} data.",
                    [project_ref["urn"], workspace_ref["urn"]],
                )
            )

    for app in object_list(posture.get("apps"), "apps"):
        if bool_value(app.get("approved_by_security"), True) == "true":
            continue
        app_key = require_value(app.get("key"), "apps[].key")
        app_name = optional_string(app.get("name")) or app_key
        app_ref = integration.ref("app", app_key, app_name)
        findings.append(
            finding(
                f"jira_app_{app_key.lower()}_unapproved",
                "MEDIUM",
                "Unapproved Jira marketplace app is installed",
                f"{app_name} is installed on {workspace_name} without security approval.",
                [app_ref["urn"], workspace_ref["urn"]],
            )
        )

    return findings


def onboard_jira_workspace_posture(
    base_url: str,
    tenant_id: str,
    runtime_id: str,
    posture: JiraWorkspacePosture,
    api_key: Optional[str] = None,
) -> OnboardJiraWorkspacePostureResult:
    posture = object_value(posture)
    workspace_key = require_value(posture.get("workspace_key"), "workspace_key")
    source_event_id = optional_string(posture.get("event_id"))
    client = Client(base_url=base_url, api_key=api_key or None)
    integration = client.integration(runtime_id=runtime_id, tenant_id=tenant_id, integration="jira")
    claims = build_jira_workspace_claims(integration, posture)
    runtime_config: Dict[str, str] = {"workspace": workspace_key}
    integration.ensure_runtime(runtime_config)
    write_result = integration.write_claims(claims, {"replace_existing": True})
    filters: Dict[str, Any] = {"limit": len(claims), "status": "asserted"}
    if source_event_id:
        filters["source_event_id"] = source_event_id
    persisted = integration.list_claims(filters)
    persisted_claims = persisted.get("claims", [])
    if not isinstance(persisted_claims, list):
        persisted_claims = []
    graph_layering = load_jira_workspace_graph_layering(integration, posture)
    return {
        "workspace_urn": claims[0]["subject_urn"],
        "write_result": write_result,
        "submitted_claims": claims,
        "persisted_claims": persisted_claims,
        "graph_layering": graph_layering,
        "graph_summary": graph_layering.get("summary", {}),
        "posture_findings": build_jira_posture_findings(
            integration,
            posture,
            graph_layering.get("summary", {}),
        ),
    }


def finding(
    finding_id: str,
    severity: str,
    title: str,
    summary: str,
    resource_urns: list[str],
    attributes: Optional[Dict[str, str]] = None,
) -> JiraPostureFinding:
    payload: JiraPostureFinding = {
        "id": finding_id,
        "severity": severity,
        "title": title,
        "summary": summary,
        "resource_urns": resource_urns,
    }
    if attributes:
        payload["attributes"] = attributes
    return payload


def bool_value(value: Any, default: bool = False) -> str:
    if value is None:
        return "true" if default else "false"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "1", "yes", "y", "on"):
            return "true"
        if normalized in ("false", "0", "no", "n", "off", ""):
            return "false"
        raise ValueError(f"invalid boolean string: {value!r}")
    raise ValueError(f"invalid boolean value: {value!r}")


def object_list(value: Any, name: str) -> list[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result: list[Dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{name}[{index}] must be an object")
        result.append(item)
    return result


def object_value(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def list_value(value: Any) -> list[Any]:
    if not isinstance(value, list):
        return []
    return value


def optional_string(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    if isinstance(value, (int, float)):
        normalized = str(value).strip()
        return normalized or None
    return None


def require_value(value: Any, name: str) -> str:
    normalized = optional_string(value)
    if normalized is None:
        raise ValueError(f"{name} is required")
    return normalized


__all__ = [
    "JiraAdminPosture",
    "JiraProjectPosture",
    "JiraMarketplaceAppPosture",
    "JiraWorkspacePosture",
    "JiraWorkspaceGraphLayering",
    "JiraPostureFinding",
    "OnboardJiraWorkspacePostureResult",
    "build_jira_workspace_claims",
    "load_jira_workspace_graph_layering",
    "build_jira_posture_findings",
    "onboard_jira_workspace_posture",
]
