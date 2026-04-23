import json
import os
from typing import Any, Dict

from cerebro_sdk import Client, IntegrationClient


def build_issue_claims(integration: IntegrationClient, issue: Dict[str, Any]) -> list[Dict[str, Any]]:
    issue_key = str(issue["key"]).strip()
    issue_ref = integration.ref("ticket", issue_key, issue_key)
    claims = [
        integration.exists(
            issue_ref,
            source_event_id=str(issue.get("event_id", "")).strip() or None,
        ),
        integration.attr(issue_ref, "summary", str(issue["summary"]).strip()),
        integration.attr(issue_ref, "status", str(issue["status"]).strip()),
    ]

    project_key = str(issue.get("project_key", "")).strip()
    if project_key:
        claims.append(
            integration.rel(
                issue_ref,
                "belongs_to",
                integration.ref("project", project_key, project_key),
            )
        )

    assignee_email = str(issue.get("assignee_email", "")).strip()
    if assignee_email:
        claims.append(
            integration.rel(
                issue_ref,
                "assigned_to",
                integration.ref("user", assignee_email, assignee_email),
            )
        )

    reporter_email = str(issue.get("reporter_email", "")).strip()
    if reporter_email:
        claims.append(
            integration.rel(
                issue_ref,
                "reported_by",
                integration.ref("user", reporter_email, reporter_email),
            )
        )

    priority = str(issue.get("priority", "")).strip()
    if priority:
        claims.append(integration.attr(issue_ref, "priority", priority))

    return claims


def onboard_issue(base_url: str, api_key: str, tenant_id: str, runtime_id: str, issue: Dict[str, Any]) -> Dict[str, Any]:
    client = Client(base_url=base_url, api_key=api_key or None)
    integration = client.integration(runtime_id=runtime_id, tenant_id=tenant_id, integration="jira")
    runtime_config = {}
    workspace = str(issue.get("workspace", "")).strip()
    if workspace:
        runtime_config["workspace"] = workspace
    integration.ensure_runtime(runtime_config)
    claims = build_issue_claims(integration, issue)
    write_result = integration.write_claims(claims)
    claim_result = integration.list_claims(
        {
            "subject_urn": claims[0]["subject_urn"],
            "limit": 20,
        }
    )
    return {
        "write_result": write_result,
        "claims": claim_result.get("claims", []),
    }


def main() -> None:
    base_url = os.environ.get("CEREBRO_BASE_URL", "").strip()
    if not base_url:
        raise RuntimeError("CEREBRO_BASE_URL is required")

    result = onboard_issue(
        base_url=base_url,
        api_key=os.environ.get("CEREBRO_API_KEY", "").strip(),
        tenant_id=os.environ.get("CEREBRO_TENANT_ID", "writer").strip(),
        runtime_id=os.environ.get("CEREBRO_RUNTIME_ID", "writer-jira").strip(),
        issue={
            "workspace": os.environ.get("JIRA_WORKSPACE", "writer").strip(),
            "event_id": os.environ.get("JIRA_EVENT_ID", "jira-event-1").strip(),
            "project_key": os.environ.get("JIRA_PROJECT_KEY", "ENG").strip(),
            "key": os.environ.get("JIRA_ISSUE_KEY", "ENG-123").strip(),
            "summary": os.environ.get("JIRA_ISSUE_SUMMARY", "Claim-first Jira onboarding example").strip(),
            "status": os.environ.get("JIRA_ISSUE_STATUS", "in_progress").strip(),
            "priority": os.environ.get("JIRA_ISSUE_PRIORITY", "high").strip(),
            "assignee_email": os.environ.get("JIRA_ASSIGNEE_EMAIL", "alice@writer.com").strip(),
            "reporter_email": os.environ.get("JIRA_REPORTER_EMAIL", "bob@writer.com").strip(),
        },
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
