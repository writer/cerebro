# Wistia

Generated Source Runtime SDK scaffold for `wistia`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/wistia`
- Health endpoint: `/source-runtimes/health?source_id=wistia`
- Source health receipt: `sources/wistia/source_health_receipt.json`
- EvidenceCAS reference kind: `wistia.evidence_cas_reference`

## Families

- `users`, emits `wistia.users`, reads `/v1/users`
- `groups`, emits `wistia.groups`, reads `/v1/groups`
- `workspaces`, emits `wistia.workspaces`, reads `/v1/workspaces`
- `documents`, emits `wistia.documents`, reads `/v1/documents`
- `audit_events`, emits `wistia.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/wistia ./internal/sourceprojection -count=1`
- `make catalog-check`
