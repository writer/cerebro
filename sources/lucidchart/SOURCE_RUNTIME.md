# Lucidchart

Generated Source Runtime SDK scaffold for `lucidchart`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/lucidchart`
- Health endpoint: `/source-runtimes/health?source_id=lucidchart`
- Source health receipt: `sources/lucidchart/source_health_receipt.json`
- EvidenceCAS reference kind: `lucidchart.evidence_cas_reference`

## Families

- `users`, emits `lucidchart.users`, reads `/v1/users`
- `groups`, emits `lucidchart.groups`, reads `/v1/groups`
- `workspaces`, emits `lucidchart.workspaces`, reads `/v1/workspaces`
- `documents`, emits `lucidchart.documents`, reads `/v1/documents`
- `audit_events`, emits `lucidchart.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/lucidchart ./internal/sourceprojection -count=1`
- `make catalog-check`
