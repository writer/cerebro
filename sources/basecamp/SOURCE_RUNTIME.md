# Basecamp

Generated Source Runtime SDK scaffold for `basecamp`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/basecamp`
- Health endpoint: `/source-runtimes/health?source_id=basecamp`
- Source health receipt: `sources/basecamp/source_health_receipt.json`
- EvidenceCAS reference kind: `basecamp.evidence_cas_reference`

## Families

- `users`, emits `basecamp.users`, reads `/v1/users`
- `groups`, emits `basecamp.groups`, reads `/v1/groups`
- `workspaces`, emits `basecamp.workspaces`, reads `/v1/workspaces`
- `documents`, emits `basecamp.documents`, reads `/v1/documents`
- `audit_events`, emits `basecamp.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/basecamp ./internal/sourceprojection -count=1`
- `make catalog-check`
