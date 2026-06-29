# Vidyard

Generated Source Runtime SDK scaffold for `vidyard`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/vidyard`
- Health endpoint: `/source-runtimes/health?source_id=vidyard`
- Source health receipt: `sources/vidyard/source_health_receipt.json`
- EvidenceCAS reference kind: `vidyard.evidence_cas_reference`

## Families

- `users`, emits `vidyard.users`, reads `/v1/users`
- `groups`, emits `vidyard.groups`, reads `/v1/groups`
- `workspaces`, emits `vidyard.workspaces`, reads `/v1/workspaces`
- `documents`, emits `vidyard.documents`, reads `/v1/documents`
- `audit_events`, emits `vidyard.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/vidyard ./internal/sourceprojection -count=1`
- `make catalog-check`
