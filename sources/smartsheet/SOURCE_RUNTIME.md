# Smartsheet

Generated Source Runtime SDK scaffold for `smartsheet`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/smartsheet`
- Health endpoint: `/source-runtimes/health?source_id=smartsheet`
- Source health receipt: `sources/smartsheet/source_health_receipt.json`
- EvidenceCAS reference kind: `smartsheet.evidence_cas_reference`

## Families

- `users`, emits `smartsheet.users`, reads `/v1/users`
- `groups`, emits `smartsheet.groups`, reads `/v1/groups`
- `workspaces`, emits `smartsheet.workspaces`, reads `/v1/workspaces`
- `documents`, emits `smartsheet.documents`, reads `/v1/documents`
- `audit_events`, emits `smartsheet.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/smartsheet ./internal/sourceprojection -count=1`
- `make catalog-check`
