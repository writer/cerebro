# Lucidscale

Generated Source Runtime SDK scaffold for `lucidscale`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/lucidscale`
- Health endpoint: `/source-runtimes/health?source_id=lucidscale`
- Source health receipt: `sources/lucidscale/source_health_receipt.json`
- EvidenceCAS reference kind: `lucidscale.evidence_cas_reference`

## Families

- `users`, emits `lucidscale.users`, reads `/v1/users`
- `groups`, emits `lucidscale.groups`, reads `/v1/groups`
- `workspaces`, emits `lucidscale.workspaces`, reads `/v1/workspaces`
- `documents`, emits `lucidscale.documents`, reads `/v1/documents`
- `audit_events`, emits `lucidscale.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/lucidscale ./internal/sourceprojection -count=1`
- `make catalog-check`
