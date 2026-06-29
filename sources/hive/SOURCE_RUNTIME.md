# Hive

Generated Source Runtime SDK scaffold for `hive`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hive`
- Health endpoint: `/source-runtimes/health?source_id=hive`
- Source health receipt: `sources/hive/source_health_receipt.json`
- EvidenceCAS reference kind: `hive.evidence_cas_reference`

## Families

- `users`, emits `hive.users`, reads `/v1/users`
- `groups`, emits `hive.groups`, reads `/v1/groups`
- `workspaces`, emits `hive.workspaces`, reads `/v1/workspaces`
- `documents`, emits `hive.documents`, reads `/v1/documents`
- `audit_events`, emits `hive.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/hive ./internal/sourceprojection -count=1`
- `make catalog-check`
