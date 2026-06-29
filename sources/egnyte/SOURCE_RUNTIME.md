# Egnyte

Generated Source Runtime SDK scaffold for `egnyte`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/egnyte`
- Health endpoint: `/source-runtimes/health?source_id=egnyte`
- Source health receipt: `sources/egnyte/source_health_receipt.json`
- EvidenceCAS reference kind: `egnyte.evidence_cas_reference`

## Families

- `users`, emits `egnyte.users`, reads `/v1/users`
- `groups`, emits `egnyte.groups`, reads `/v1/groups`
- `workspaces`, emits `egnyte.workspaces`, reads `/v1/workspaces`
- `documents`, emits `egnyte.documents`, reads `/v1/documents`
- `audit_events`, emits `egnyte.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/egnyte ./internal/sourceprojection -count=1`
- `make catalog-check`
