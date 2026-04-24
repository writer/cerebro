import json
import os
from typing import Any, Dict, Optional

from cerebro_sdk import Client, IntegrationClient


def build_workspace_claims(integration: IntegrationClient, posture: Dict[str, Any]) -> list[Dict[str, Any]]:
    workspace_key = require_value(posture.get("workspace_key"), "workspace_key")
    workspace_name = optional_string(posture.get("workspace_name")) or workspace_key
    workspace_ref = integration.ref("workspace", workspace_key, workspace_name)
    source_event_id = optional_string(posture.get("event_id"))
    shared_options = {"source_event_id": source_event_id} if source_event_id else {}
    admins = list(posture.get("admins", []))
    projects = list(posture.get("projects", []))
    apps = list(posture.get("apps", []))

    claims = [
        integration.exists(workspace_ref, **shared_options),
        integration.attr(workspace_ref, "platform", "jira", **shared_options),
        integration.attr(workspace_ref, "vendor", "atlassian", **shared_options),
        integration.attr(workspace_ref, "sso_enforced", bool_value(posture.get("sso_enforced", True)), **shared_options),
        integration.attr(
            workspace_ref,
            "mfa_required_for_admins",
            bool_value(posture.get("mfa_required_for_admins", True)),
            **shared_options,
        ),
        integration.attr(
            workspace_ref,
            "atlassian_guard_enabled",
            bool_value(posture.get("atlassian_guard_enabled", True)),
            **shared_options,
        ),
        integration.attr(
            workspace_ref,
            "audit_log_export_enabled",
            bool_value(posture.get("audit_log_export_enabled", True)),
            **shared_options,
        ),
        integration.attr(
            workspace_ref,
            "api_token_expiration_enforced",
            bool_value(posture.get("api_token_expiration_enforced", True)),
            **shared_options,
        ),
        integration.attr(
            workspace_ref,
            "public_signup_enabled",
            bool_value(posture.get("public_signup_enabled", False)),
            **shared_options,
        ),
        integration.attr(
            workspace_ref,
            "anonymous_access_enabled",
            bool_value(posture.get("anonymous_access_enabled", False)),
            **shared_options,
        ),
        integration.attr(
            workspace_ref,
            "approved_marketplace_apps_only",
            bool_value(posture.get("approved_marketplace_apps_only", True)),
            **shared_options,
        ),
        integration.attr(workspace_ref, "admin_count", str(len(admins)), **shared_options),
        integration.attr(workspace_ref, "project_count", str(len(projects)), **shared_options),
        integration.attr(workspace_ref, "installed_app_count", str(len(apps)), **shared_options),
    ]

    for admin in admins:
        email = require_value(admin.get("email"), "admins[].email")
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
                bool_value(project.get("issue_level_security_enabled", True)),
                **shared_options,
            )
        )
        claims.append(
            integration.attr(
                project_ref,
                "anonymous_browse_enabled",
                bool_value(project.get("anonymous_browse_enabled", False)),
                **shared_options,
            )
        )
        claims.append(
            integration.attr(
                project_ref,
                "service_desk_public_portal_enabled",
                bool_value(project.get("service_desk_public_portal_enabled", False)),
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
                bool_value(app.get("approved_by_security", True)),
                **shared_options,
            )
        )
        scopes = [optional_string(scope) for scope in app.get("scopes", [])]
        normalized_scopes = [scope for scope in scopes if scope]
        if normalized_scopes:
            claims.append(integration.attr(app_ref, "scopes", ",".join(normalized_scopes), **shared_options))

    return claims


def onboard_workspace_posture(
    base_url: str,
    api_key: str,
    tenant_id: str,
    runtime_id: str,
    posture: Dict[str, Any],
) -> Dict[str, Any]:
    client = Client(base_url=base_url, api_key=api_key or None)
    integration = client.integration(runtime_id=runtime_id, tenant_id=tenant_id, integration="jira")
    runtime_config = {}
    workspace_key = optional_string(posture.get("workspace_key"))
    if workspace_key:
        runtime_config["workspace"] = workspace_key
    integration.ensure_runtime(runtime_config)
    claims = build_workspace_claims(integration, posture)
    write_result = integration.write_claims(claims)
    persisted = integration.list_claims({"limit": 100})
    graph_layering = load_graph_layering(integration, posture)
    return {
        "workspace_urn": claims[0]["subject_urn"],
        "write_result": write_result,
        "submitted_claims": claims,
        "persisted_claims": persisted.get("claims", []),
        "graph_layering": graph_layering,
        "graph_summary": graph_layering.get("summary", {}),
    }


def main() -> None:
    base_url = require_value(os.environ.get("CEREBRO_BASE_URL"), "CEREBRO_BASE_URL")
    result = onboard_workspace_posture(
        base_url=base_url,
        api_key=optional_string(os.environ.get("CEREBRO_API_KEY")) or "",
        tenant_id=optional_string(os.environ.get("CEREBRO_TENANT_ID")) or "writer",
        runtime_id=optional_string(os.environ.get("CEREBRO_RUNTIME_ID")) or "writer-jira-posture",
        posture={
            "workspace_key": optional_string(os.environ.get("JIRA_WORKSPACE")) or "writer",
            "workspace_name": optional_string(os.environ.get("JIRA_WORKSPACE_NAME")) or "Writer Jira",
            "event_id": optional_string(os.environ.get("JIRA_EVENT_ID")) or "jira-posture-snapshot-1",
            "sso_enforced": env_bool("JIRA_SSO_ENFORCED", True),
            "mfa_required_for_admins": env_bool("JIRA_MFA_REQUIRED_FOR_ADMINS", True),
            "atlassian_guard_enabled": env_bool("JIRA_ATLASSIAN_GUARD_ENABLED", True),
            "audit_log_export_enabled": env_bool("JIRA_AUDIT_LOG_EXPORT_ENABLED", True),
            "api_token_expiration_enforced": env_bool("JIRA_API_TOKEN_EXPIRATION_ENFORCED", True),
            "public_signup_enabled": env_bool("JIRA_PUBLIC_SIGNUP_ENABLED", False),
            "anonymous_access_enabled": env_bool("JIRA_ANONYMOUS_ACCESS_ENABLED", False),
            "approved_marketplace_apps_only": env_bool("JIRA_APPROVED_MARKETPLACE_APPS_ONLY", True),
            "admins": [
                {
                    "email": optional_string(os.environ.get("JIRA_ADMIN_1_EMAIL")) or "alice@writer.com",
                    "display_name": optional_string(os.environ.get("JIRA_ADMIN_1_NAME")) or "Alice",
                    "role": optional_string(os.environ.get("JIRA_ADMIN_1_ROLE")) or "site_admin",
                },
                {
                    "email": optional_string(os.environ.get("JIRA_ADMIN_2_EMAIL")) or "bob@writer.com",
                    "display_name": optional_string(os.environ.get("JIRA_ADMIN_2_NAME")) or "Bob",
                    "role": optional_string(os.environ.get("JIRA_ADMIN_2_ROLE")) or "org_admin",
                },
            ],
            "projects": [
                {
                    "key": optional_string(os.environ.get("JIRA_PROJECT_1_KEY")) or "ENG",
                    "name": optional_string(os.environ.get("JIRA_PROJECT_1_NAME")) or "Engineering",
                    "classification": optional_string(os.environ.get("JIRA_PROJECT_1_CLASSIFICATION")) or "internal",
                    "issue_level_security_enabled": env_bool("JIRA_PROJECT_1_ISSUE_SECURITY_ENABLED", True),
                    "anonymous_browse_enabled": env_bool("JIRA_PROJECT_1_ANONYMOUS_BROWSE_ENABLED", False),
                    "service_desk_public_portal_enabled": env_bool("JIRA_PROJECT_1_PUBLIC_PORTAL_ENABLED", False),
                },
                {
                    "key": optional_string(os.environ.get("JIRA_PROJECT_2_KEY")) or "SEC",
                    "name": optional_string(os.environ.get("JIRA_PROJECT_2_NAME")) or "Security",
                    "classification": optional_string(os.environ.get("JIRA_PROJECT_2_CLASSIFICATION")) or "restricted",
                    "issue_level_security_enabled": env_bool("JIRA_PROJECT_2_ISSUE_SECURITY_ENABLED", True),
                    "anonymous_browse_enabled": env_bool("JIRA_PROJECT_2_ANONYMOUS_BROWSE_ENABLED", False),
                    "service_desk_public_portal_enabled": env_bool("JIRA_PROJECT_2_PUBLIC_PORTAL_ENABLED", False),
                },
            ],
            "apps": [
                {
                    "key": optional_string(os.environ.get("JIRA_APP_1_KEY")) or "slack",
                    "name": optional_string(os.environ.get("JIRA_APP_1_NAME")) or "Slack for Jira",
                    "approved_by_security": env_bool("JIRA_APP_1_APPROVED_BY_SECURITY", True),
                    "scopes": [
                        optional_string(os.environ.get("JIRA_APP_1_SCOPE_1")) or "read:project:jira",
                        optional_string(os.environ.get("JIRA_APP_1_SCOPE_2")) or "write:comment:jira",
                    ],
                }
            ],
        },
    )
    print(json.dumps(result, indent=2, sort_keys=True))


def env_bool(name: str, default: bool) -> bool:
    raw = optional_string(os.environ.get(name))
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def bool_value(value: Any) -> str:
    return "true" if bool(value) else "false"


def load_graph_layering(integration: IntegrationClient, posture: Dict[str, Any]) -> Dict[str, Any]:
    workspace_key = require_value(posture.get("workspace_key"), "workspace_key")
    workspace_name = optional_string(posture.get("workspace_name")) or workspace_key
    workspace_ref = integration.ref("workspace", workspace_key, workspace_name)
    project_refs = []
    project_keys = []
    for project in posture.get("projects", []):
        project_key = require_value(project.get("key"), "projects[].key")
        project_name = optional_string(project.get("name")) or project_key
        project_refs.append(integration.ref("project", project_key, project_name))
        project_keys.append(project_key)
    workspace_graph = integration.graph_layering([workspace_ref], limit=50)
    project_layering = integration.graph_layering(project_refs, limit=12)
    combined_layering = dict(workspace_graph)
    combined_layering.update(project_layering)
    project_graphs = {}
    for project_key, project_ref in zip(project_keys, project_refs):
        project_graphs[project_key] = project_layering.get(project_ref["urn"], {"root_urn": project_ref["urn"], "error": "missing graph response"})
    return {
        "workspace": workspace_graph.get(workspace_ref["urn"], {"root_urn": workspace_ref["urn"], "error": "missing graph response"}),
        "projects": project_graphs,
        "summary": integration.graph_summary(combined_layering),
    }


def optional_string(value: Any) -> Optional[str]:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def require_value(value: Any, name: str) -> str:
    normalized = optional_string(value)
    if normalized is None:
        raise ValueError(f"{name} is required")
    return normalized


if __name__ == "__main__":
    main()
