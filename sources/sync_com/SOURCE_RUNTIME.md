# Sync.com

Generated Source Runtime SDK scaffold for `sync_com`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sync_com`
- Health endpoint: `/source-runtimes/health?source_id=sync_com`
- Source health receipt: `sources/sync_com/source_health_receipt.json`
- EvidenceCAS reference kind: `sync_com.evidence_cas_reference`

## Families

- `users`, emits `sync_com.users`, reads `/v1/users`
- `groups`, emits `sync_com.groups`, reads `/v1/groups`
- `workspaces`, emits `sync_com.workspaces`, reads `/v1/workspaces`
- `documents`, emits `sync_com.documents`, reads `/v1/documents`
- `audit_events`, emits `sync_com.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sync_com ./internal/sourceprojection -count=1`
- `make catalog-check`
