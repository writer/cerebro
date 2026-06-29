# Coda

Generated Source Runtime SDK scaffold for `coda`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/coda`
- Health endpoint: `/source-runtimes/health?source_id=coda`
- Source health receipt: `sources/coda/source_health_receipt.json`
- EvidenceCAS reference kind: `coda.evidence_cas_reference`

## Families

- `users`, emits `coda.users`, reads `/v1/users`
- `groups`, emits `coda.groups`, reads `/v1/groups`
- `workspaces`, emits `coda.workspaces`, reads `/v1/workspaces`
- `documents`, emits `coda.documents`, reads `/v1/documents`
- `audit_events`, emits `coda.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/coda ./internal/sourceprojection -count=1`
- `make catalog-check`
