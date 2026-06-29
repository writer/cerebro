# Sharefile

Generated Source Runtime SDK scaffold for `sharefile`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sharefile`
- Health endpoint: `/source-runtimes/health?source_id=sharefile`
- Source health receipt: `sources/sharefile/source_health_receipt.json`
- EvidenceCAS reference kind: `sharefile.evidence_cas_reference`

## Families

- `users`, emits `sharefile.users`, reads `/v1/users`
- `groups`, emits `sharefile.groups`, reads `/v1/groups`
- `workspaces`, emits `sharefile.workspaces`, reads `/v1/workspaces`
- `documents`, emits `sharefile.documents`, reads `/v1/documents`
- `audit_events`, emits `sharefile.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sharefile ./internal/sourceprojection -count=1`
- `make catalog-check`
