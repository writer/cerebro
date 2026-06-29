# Drift

Generated Source Runtime SDK scaffold for `drift`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/drift`
- Health endpoint: `/source-runtimes/health?source_id=drift`
- Source health receipt: `sources/drift/source_health_receipt.json`
- EvidenceCAS reference kind: `drift.evidence_cas_reference`

## Families

- `users`, emits `drift.users`, reads `/v1/users`
- `groups`, emits `drift.groups`, reads `/v1/groups`
- `workspaces`, emits `drift.workspaces`, reads `/v1/workspaces`
- `documents`, emits `drift.documents`, reads `/v1/documents`
- `audit_events`, emits `drift.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/drift ./internal/sourceprojection -count=1`
- `make catalog-check`
