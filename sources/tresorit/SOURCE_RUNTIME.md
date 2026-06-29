# Tresorit

Generated Source Runtime SDK scaffold for `tresorit`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/tresorit`
- Health endpoint: `/source-runtimes/health?source_id=tresorit`
- Source health receipt: `sources/tresorit/source_health_receipt.json`
- EvidenceCAS reference kind: `tresorit.evidence_cas_reference`

## Families

- `users`, emits `tresorit.users`, reads `/v1/users`
- `groups`, emits `tresorit.groups`, reads `/v1/groups`
- `workspaces`, emits `tresorit.workspaces`, reads `/v1/workspaces`
- `documents`, emits `tresorit.documents`, reads `/v1/documents`
- `audit_events`, emits `tresorit.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/tresorit ./internal/sourceprojection -count=1`
- `make catalog-check`
