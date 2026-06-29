# Nuclino

Generated Source Runtime SDK scaffold for `nuclino`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/nuclino`
- Health endpoint: `/source-runtimes/health?source_id=nuclino`
- Source health receipt: `sources/nuclino/source_health_receipt.json`
- EvidenceCAS reference kind: `nuclino.evidence_cas_reference`

## Families

- `users`, emits `nuclino.users`, reads `/v1/users`
- `groups`, emits `nuclino.groups`, reads `/v1/groups`
- `workspaces`, emits `nuclino.workspaces`, reads `/v1/workspaces`
- `documents`, emits `nuclino.documents`, reads `/v1/documents`
- `audit_events`, emits `nuclino.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/nuclino ./internal/sourceprojection -count=1`
- `make catalog-check`
