# Clicksend

Generated Source Runtime SDK scaffold for `clicksend`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/clicksend`
- Health endpoint: `/source-runtimes/health?source_id=clicksend`
- Source health receipt: `sources/clicksend/source_health_receipt.json`
- EvidenceCAS reference kind: `clicksend.evidence_cas_reference`

## Families

- `users`, emits `clicksend.users`, reads `/v1/users`
- `groups`, emits `clicksend.groups`, reads `/v1/groups`
- `workspaces`, emits `clicksend.workspaces`, reads `/v1/workspaces`
- `documents`, emits `clicksend.documents`, reads `/v1/documents`
- `audit_events`, emits `clicksend.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/clicksend ./internal/sourceprojection -count=1`
- `make catalog-check`
