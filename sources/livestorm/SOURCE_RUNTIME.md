# Livestorm

Generated Source Runtime SDK scaffold for `livestorm`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/livestorm`
- Health endpoint: `/source-runtimes/health?source_id=livestorm`
- Source health receipt: `sources/livestorm/source_health_receipt.json`
- EvidenceCAS reference kind: `livestorm.evidence_cas_reference`

## Families

- `users`, emits `livestorm.users`, reads `/v1/users`
- `groups`, emits `livestorm.groups`, reads `/v1/groups`
- `workspaces`, emits `livestorm.workspaces`, reads `/v1/workspaces`
- `documents`, emits `livestorm.documents`, reads `/v1/documents`
- `audit_events`, emits `livestorm.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/livestorm ./internal/sourceprojection -count=1`
- `make catalog-check`
