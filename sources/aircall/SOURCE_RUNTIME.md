# Aircall

Generated Source Runtime SDK scaffold for `aircall`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/aircall`
- Health endpoint: `/source-runtimes/health?source_id=aircall`
- Source health receipt: `sources/aircall/source_health_receipt.json`
- EvidenceCAS reference kind: `aircall.evidence_cas_reference`

## Families

- `users`, emits `aircall.users`, reads `/v1/users`
- `groups`, emits `aircall.groups`, reads `/v1/groups`
- `workspaces`, emits `aircall.workspaces`, reads `/v1/workspaces`
- `documents`, emits `aircall.documents`, reads `/v1/documents`
- `audit_events`, emits `aircall.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/aircall ./internal/sourceprojection -count=1`
- `make catalog-check`
