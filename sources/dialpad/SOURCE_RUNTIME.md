# Dialpad

Generated Source Runtime SDK scaffold for `dialpad`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/dialpad`
- Health endpoint: `/source-runtimes/health?source_id=dialpad`
- Source health receipt: `sources/dialpad/source_health_receipt.json`
- EvidenceCAS reference kind: `dialpad.evidence_cas_reference`

## Families

- `users`, emits `dialpad.users`, reads `/v1/users`
- `groups`, emits `dialpad.groups`, reads `/v1/groups`
- `workspaces`, emits `dialpad.workspaces`, reads `/v1/workspaces`
- `documents`, emits `dialpad.documents`, reads `/v1/documents`
- `audit_events`, emits `dialpad.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/dialpad ./internal/sourceprojection -count=1`
- `make catalog-check`
