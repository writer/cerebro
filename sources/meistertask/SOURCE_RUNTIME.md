# Meistertask

Generated Source Runtime SDK scaffold for `meistertask`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/meistertask`
- Health endpoint: `/source-runtimes/health?source_id=meistertask`
- Source health receipt: `sources/meistertask/source_health_receipt.json`
- EvidenceCAS reference kind: `meistertask.evidence_cas_reference`

## Families

- `users`, emits `meistertask.users`, reads `/v1/users`
- `groups`, emits `meistertask.groups`, reads `/v1/groups`
- `workspaces`, emits `meistertask.workspaces`, reads `/v1/workspaces`
- `documents`, emits `meistertask.documents`, reads `/v1/documents`
- `audit_events`, emits `meistertask.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/meistertask ./internal/sourceprojection -count=1`
- `make catalog-check`
