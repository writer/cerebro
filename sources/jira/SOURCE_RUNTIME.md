# Jira

Source Runtime SDK adapter for Jira Cloud REST API v3.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Credentials: Jira account email as `username`, Jira API token as `password`
- Base URL: `https://${config.site_url}`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/jira`
- Health endpoint: `/source-runtimes/health?source_id=jira`
- Source health receipt: `sources/jira/source_health_receipt.json`
- EvidenceCAS reference kind: `jira.evidence_cas_reference`

## Families

- `users`, emits `jira.users`, reads `/rest/api/3/users/search`
- `groups`, emits `jira.groups`, reads `/rest/api/3/group/bulk`
- `group_members`, emits `jira.group_members`, fans out configured `group_ids` through `/rest/api/3/group/member`
- `projects`, emits `jira.projects`, reads `/rest/api/3/project/search`
- `project_roles`, emits `jira.project_roles`, fans out configured `project_id_or_keys` through `/rest/api/3/project/{project_id_or_key}/roledetails` and enriches roles from `/rest/api/3/project/{project_id_or_key}/role/{id}`
- `permission_schemes`, emits `jira.permission_schemes`, reads `/rest/api/3/permissionscheme?expand=permissions`
- `audit_events`, emits `jira.audit_events`, reads `/rest/api/3/auditing/record`

## Graph projection

- Users and groups project to Jira identity entities.
- Group member records project user-to-group membership links.
- Projects project first-class `jira.project` entities and project-lead ownership links.
- Project role records project role entities and actor assignments for users and groups.
- Permission schemes project permission scheme entities, permission grant entities, and holder entitlement links for users, groups, project roles, application roles, and principals.
- Audit records project audit event entities and acted-on resource links when object metadata is present.

## Tests

- `go test ./sources/jira ./sources/internal/jiraapi ./sources/internal/jsonapi ./internal/sourceprojection -count=1`
- `make catalog-check`
