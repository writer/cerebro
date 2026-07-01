## Summary

- Replaces the Jira scaffold with a Jira Cloud REST API v3 runtime.
- Adds real API families for users, groups, group members, projects, project roles, permission schemes, and audit records.
- Projects Jira identity, project, role, permission, and audit records into graph entities and links.

## Runtime contract

- Source type: `json_api`
- Auth model: `basic`
- Base URL: `https://${config.site_url}`
- Health check: `GET /rest/api/3/myself`
- Family endpoints:
  - `GET /rest/api/3/users/search`
  - `GET /rest/api/3/group/bulk`
  - `GET /rest/api/3/group/member`
  - `GET /rest/api/3/project/search`
  - `GET /rest/api/3/project/{project_id_or_key}/roledetails`
  - `GET /rest/api/3/project/{project_id_or_key}/role/{id}`
  - `GET /rest/api/3/permissionscheme?expand=permissions`
  - `GET /rest/api/3/auditing/record`

## Graph projection

- `jira.users`, `jira.groups`, and `jira.group_members` use identity projectors.
- `jira.projects` projects project assets and lead ownership.
- `jira.project_roles` projects project roles, admin roles, and actor assignments.
- `jira.permission_schemes` projects permission schemes, permission grants, and holder entitlement links.
- `jira.audit_events` projects audit records with acted-on resource context.

## Tests

- `go test ./sources/jira ./sources/internal/jiraapi ./sources/internal/jsonapi ./internal/sourceprojection -count=1`
- `make sourcegen-test`
- `make sourcegen-check`
- `make catalog-check`
- `make connector-catalog-fidelity-check`
- `make connector-contract-check`
- `make docs-drift-check`
- `make projection-template-check`
- `go test ./tools/archtests -run 'TestSourceDeploy|TestPrioritySourceHealthReceipts|TestGeneratedFiles' -count=1`
- `make droid-review-sast`
