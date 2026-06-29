# Zoho Sprints

Generated Source Runtime SDK scaffold for `zoho_sprints`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zoho_sprints`
- Health endpoint: `/source-runtimes/health?source_id=zoho_sprints`
- Source health receipt: `sources/zoho_sprints/source_health_receipt.json`
- EvidenceCAS reference kind: `zoho_sprints.evidence_cas_reference`

## Families

- `users`, emits `zoho_sprints.users`, reads `/v1/users`
- `groups`, emits `zoho_sprints.groups`, reads `/v1/groups`
- `workspaces`, emits `zoho_sprints.workspaces`, reads `/v1/workspaces`
- `documents`, emits `zoho_sprints.documents`, reads `/v1/documents`
- `audit_events`, emits `zoho_sprints.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zoho_sprints ./internal/sourceprojection -count=1`
- `make catalog-check`
