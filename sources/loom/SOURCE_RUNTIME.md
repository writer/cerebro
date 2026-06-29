# Loom

Generated Source Runtime SDK scaffold for `loom`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/loom`
- Health endpoint: `/source-runtimes/health?source_id=loom`
- Source health receipt: `sources/loom/source_health_receipt.json`
- EvidenceCAS reference kind: `loom.evidence_cas_reference`

## Families

- `users`, emits `loom.users`, reads `/v1/users`
- `groups`, emits `loom.groups`, reads `/v1/groups`
- `workspaces`, emits `loom.workspaces`, reads `/v1/workspaces`
- `documents`, emits `loom.documents`, reads `/v1/documents`
- `audit_events`, emits `loom.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/loom ./internal/sourceprojection -count=1`
- `make catalog-check`
