# Calendly

Generated Source Runtime SDK scaffold for `calendly`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/calendly`
- Health endpoint: `/source-runtimes/health?source_id=calendly`
- Source health receipt: `sources/calendly/source_health_receipt.json`
- EvidenceCAS reference kind: `calendly.evidence_cas_reference`

## Families

- `users`, emits `calendly.users`, reads `/v1/users`
- `groups`, emits `calendly.groups`, reads `/v1/groups`
- `workspaces`, emits `calendly.workspaces`, reads `/v1/workspaces`
- `documents`, emits `calendly.documents`, reads `/v1/documents`
- `audit_events`, emits `calendly.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/calendly ./internal/sourceprojection -count=1`
- `make catalog-check`
