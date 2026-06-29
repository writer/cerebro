# Workplace From Meta

Generated Source Runtime SDK scaffold for `workplace_from_meta`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/workplace_from_meta`
- Health endpoint: `/source-runtimes/health?source_id=workplace_from_meta`
- Source health receipt: `sources/workplace_from_meta/source_health_receipt.json`
- EvidenceCAS reference kind: `workplace_from_meta.evidence_cas_reference`

## Families

- `users`, emits `workplace_from_meta.users`, reads `/v1/users`
- `groups`, emits `workplace_from_meta.groups`, reads `/v1/groups`
- `workspaces`, emits `workplace_from_meta.workspaces`, reads `/v1/workspaces`
- `documents`, emits `workplace_from_meta.documents`, reads `/v1/documents`
- `audit_events`, emits `workplace_from_meta.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/workplace_from_meta ./internal/sourceprojection -count=1`
- `make catalog-check`
