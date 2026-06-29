# Tettra

Generated Source Runtime SDK scaffold for `tettra`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/tettra`
- Health endpoint: `/source-runtimes/health?source_id=tettra`
- Source health receipt: `sources/tettra/source_health_receipt.json`
- EvidenceCAS reference kind: `tettra.evidence_cas_reference`

## Families

- `users`, emits `tettra.users`, reads `/v1/users`
- `groups`, emits `tettra.groups`, reads `/v1/groups`
- `workspaces`, emits `tettra.workspaces`, reads `/v1/workspaces`
- `documents`, emits `tettra.documents`, reads `/v1/documents`
- `audit_events`, emits `tettra.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/tettra ./internal/sourceprojection -count=1`
- `make catalog-check`
