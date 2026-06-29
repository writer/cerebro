# Guru

Generated Source Runtime SDK scaffold for `guru`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/guru`
- Health endpoint: `/source-runtimes/health?source_id=guru`
- Source health receipt: `sources/guru/source_health_receipt.json`
- EvidenceCAS reference kind: `guru.evidence_cas_reference`

## Families

- `users`, emits `guru.users`, reads `/v1/users`
- `groups`, emits `guru.groups`, reads `/v1/groups`
- `workspaces`, emits `guru.workspaces`, reads `/v1/workspaces`
- `documents`, emits `guru.documents`, reads `/v1/documents`
- `audit_events`, emits `guru.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/guru ./internal/sourceprojection -count=1`
- `make catalog-check`
