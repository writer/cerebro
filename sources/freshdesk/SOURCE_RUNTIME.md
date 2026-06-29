# Freshdesk

Generated Source Runtime SDK scaffold for `freshdesk`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/freshdesk`
- Health endpoint: `/source-runtimes/health?source_id=freshdesk`
- Source health receipt: `sources/freshdesk/source_health_receipt.json`
- EvidenceCAS reference kind: `freshdesk.evidence_cas_reference`

## Families

- `users`, emits `freshdesk.users`, reads `/v1/users`
- `groups`, emits `freshdesk.groups`, reads `/v1/groups`
- `workspaces`, emits `freshdesk.workspaces`, reads `/v1/workspaces`
- `documents`, emits `freshdesk.documents`, reads `/v1/documents`
- `audit_events`, emits `freshdesk.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/freshdesk ./internal/sourceprojection -count=1`
- `make catalog-check`
