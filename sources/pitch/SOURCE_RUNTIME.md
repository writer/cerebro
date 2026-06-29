# Pitch

Generated Source Runtime SDK scaffold for `pitch`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/pitch`
- Health endpoint: `/source-runtimes/health?source_id=pitch`
- Source health receipt: `sources/pitch/source_health_receipt.json`
- EvidenceCAS reference kind: `pitch.evidence_cas_reference`

## Families

- `users`, emits `pitch.users`, reads `/v1/users`
- `groups`, emits `pitch.groups`, reads `/v1/groups`
- `workspaces`, emits `pitch.workspaces`, reads `/v1/workspaces`
- `documents`, emits `pitch.documents`, reads `/v1/documents`
- `audit_events`, emits `pitch.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/pitch ./internal/sourceprojection -count=1`
- `make catalog-check`
