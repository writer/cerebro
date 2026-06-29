# Mural

Generated Source Runtime SDK scaffold for `mural`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mural`
- Health endpoint: `/source-runtimes/health?source_id=mural`
- Source health receipt: `sources/mural/source_health_receipt.json`
- EvidenceCAS reference kind: `mural.evidence_cas_reference`

## Families

- `users`, emits `mural.users`, reads `/v1/users`
- `groups`, emits `mural.groups`, reads `/v1/groups`
- `workspaces`, emits `mural.workspaces`, reads `/v1/workspaces`
- `documents`, emits `mural.documents`, reads `/v1/documents`
- `audit_events`, emits `mural.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/mural ./internal/sourceprojection -count=1`
- `make catalog-check`
