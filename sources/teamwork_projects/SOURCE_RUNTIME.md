# Teamwork Projects

Generated Source Runtime SDK scaffold for `teamwork_projects`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/teamwork_projects`
- Health endpoint: `/source-runtimes/health?source_id=teamwork_projects`
- Source health receipt: `sources/teamwork_projects/source_health_receipt.json`
- EvidenceCAS reference kind: `teamwork_projects.evidence_cas_reference`

## Families

- `users`, emits `teamwork_projects.users`, reads `/v1/users`
- `groups`, emits `teamwork_projects.groups`, reads `/v1/groups`
- `workspaces`, emits `teamwork_projects.workspaces`, reads `/v1/workspaces`
- `documents`, emits `teamwork_projects.documents`, reads `/v1/documents`
- `audit_events`, emits `teamwork_projects.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/teamwork_projects ./internal/sourceprojection -count=1`
- `make catalog-check`
