# Hightail

Generated Source Runtime SDK scaffold for `hightail`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hightail`
- Health endpoint: `/source-runtimes/health?source_id=hightail`
- Source health receipt: `sources/hightail/source_health_receipt.json`
- EvidenceCAS reference kind: `hightail.evidence_cas_reference`

## Families

- `users`, emits `hightail.users`, reads `/v1/users`
- `groups`, emits `hightail.groups`, reads `/v1/groups`
- `workspaces`, emits `hightail.workspaces`, reads `/v1/workspaces`
- `documents`, emits `hightail.documents`, reads `/v1/documents`
- `audit_events`, emits `hightail.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/hightail ./internal/sourceprojection -count=1`
- `make catalog-check`
