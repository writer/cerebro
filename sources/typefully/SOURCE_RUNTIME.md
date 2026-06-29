# Typefully

Generated Source Runtime SDK scaffold for `typefully`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/typefully`
- Health endpoint: `/source-runtimes/health?source_id=typefully`
- Source health receipt: `sources/typefully/source_health_receipt.json`
- EvidenceCAS reference kind: `typefully.evidence_cas_reference`

## Families

- `users`, emits `typefully.users`, reads `/v1/users`
- `groups`, emits `typefully.groups`, reads `/v1/groups`
- `workspaces`, emits `typefully.workspaces`, reads `/v1/workspaces`
- `documents`, emits `typefully.documents`, reads `/v1/documents`
- `audit_events`, emits `typefully.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/typefully ./internal/sourceprojection -count=1`
- `make catalog-check`
