# Frontify

Generated Source Runtime SDK scaffold for `frontify`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/frontify`
- Health endpoint: `/source-runtimes/health?source_id=frontify`
- Source health receipt: `sources/frontify/source_health_receipt.json`
- EvidenceCAS reference kind: `frontify.evidence_cas_reference`

## Families

- `users`, emits `frontify.users`, reads `/v1/users`
- `groups`, emits `frontify.groups`, reads `/v1/groups`
- `workspaces`, emits `frontify.workspaces`, reads `/v1/workspaces`
- `documents`, emits `frontify.documents`, reads `/v1/documents`
- `audit_events`, emits `frontify.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/frontify ./internal/sourceprojection -count=1`
- `make catalog-check`
