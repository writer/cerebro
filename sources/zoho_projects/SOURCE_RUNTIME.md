# Zoho Projects

Generated Source Runtime SDK scaffold for `zoho_projects`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zoho_projects`
- Health endpoint: `/source-runtimes/health?source_id=zoho_projects`
- Source health receipt: `sources/zoho_projects/source_health_receipt.json`
- EvidenceCAS reference kind: `zoho_projects.evidence_cas_reference`

## Families

- `users`, emits `zoho_projects.users`, reads `/v1/users`
- `groups`, emits `zoho_projects.groups`, reads `/v1/groups`
- `workspaces`, emits `zoho_projects.workspaces`, reads `/v1/workspaces`
- `documents`, emits `zoho_projects.documents`, reads `/v1/documents`
- `audit_events`, emits `zoho_projects.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zoho_projects ./internal/sourceprojection -count=1`
- `make catalog-check`
