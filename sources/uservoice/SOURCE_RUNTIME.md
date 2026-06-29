# Uservoice

Generated Source Runtime SDK scaffold for `uservoice`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/uservoice`
- Health endpoint: `/source-runtimes/health?source_id=uservoice`
- Source health receipt: `sources/uservoice/source_health_receipt.json`
- EvidenceCAS reference kind: `uservoice.evidence_cas_reference`

## Families

- `users`, emits `uservoice.users`, reads `/v1/users`
- `groups`, emits `uservoice.groups`, reads `/v1/groups`
- `workspaces`, emits `uservoice.workspaces`, reads `/v1/workspaces`
- `documents`, emits `uservoice.documents`, reads `/v1/documents`
- `audit_events`, emits `uservoice.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/uservoice ./internal/sourceprojection -count=1`
- `make catalog-check`
