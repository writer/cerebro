import json
import os
from typing import Any, Optional

from cerebro_sdk import JiraWorkspacePosture, onboard_jira_workspace_posture


def main() -> None:
    base_url = require_value(os.environ.get("CEREBRO_BASE_URL"), "CEREBRO_BASE_URL")
    result = onboard_jira_workspace_posture(
        base_url=base_url,
        api_key=optional_string(os.environ.get("CEREBRO_API_KEY")),
        tenant_id=optional_string(os.environ.get("CEREBRO_TENANT_ID")) or "writer",
        runtime_id=optional_string(os.environ.get("CEREBRO_RUNTIME_ID")) or "writer-jira-posture",
        posture=build_workspace_posture_from_env(),
    )
    print(json.dumps(result, indent=2, sort_keys=True))


def build_workspace_posture_from_env() -> JiraWorkspacePosture:
    return {
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
    }


def env_bool(name: str, default: bool) -> bool:
    raw = optional_string(os.environ.get(name))
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


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
