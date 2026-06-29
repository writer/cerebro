# Gorgias

Generated Source Runtime SDK scaffold for `gorgias`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gorgias`
- Health endpoint: `/source-runtimes/health?source_id=gorgias`
- Source health receipt: `sources/gorgias/source_health_receipt.json`
- EvidenceCAS reference kind: `gorgias.evidence_cas_reference`

## Families

- `users`, emits `gorgias.users`, reads `/v1/users`
- `groups`, emits `gorgias.groups`, reads `/v1/groups`
- `workspaces`, emits `gorgias.workspaces`, reads `/v1/workspaces`
- `documents`, emits `gorgias.documents`, reads `/v1/documents`
- `audit_events`, emits `gorgias.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/gorgias ./internal/sourceprojection -count=1`
- `make catalog-check`
