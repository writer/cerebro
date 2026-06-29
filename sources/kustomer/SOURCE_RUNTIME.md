# Kustomer

Generated Source Runtime SDK scaffold for `kustomer`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/kustomer`
- Health endpoint: `/source-runtimes/health?source_id=kustomer`
- Source health receipt: `sources/kustomer/source_health_receipt.json`
- EvidenceCAS reference kind: `kustomer.evidence_cas_reference`

## Families

- `users`, emits `kustomer.users`, reads `/v1/users`
- `groups`, emits `kustomer.groups`, reads `/v1/groups`
- `workspaces`, emits `kustomer.workspaces`, reads `/v1/workspaces`
- `documents`, emits `kustomer.documents`, reads `/v1/documents`
- `audit_events`, emits `kustomer.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/kustomer ./internal/sourceprojection -count=1`
- `make catalog-check`
