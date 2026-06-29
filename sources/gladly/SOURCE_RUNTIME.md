# Gladly

Generated Source Runtime SDK scaffold for `gladly`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gladly`
- Health endpoint: `/source-runtimes/health?source_id=gladly`
- Source health receipt: `sources/gladly/source_health_receipt.json`
- EvidenceCAS reference kind: `gladly.evidence_cas_reference`

## Families

- `users`, emits `gladly.users`, reads `/v1/users`
- `groups`, emits `gladly.groups`, reads `/v1/groups`
- `workspaces`, emits `gladly.workspaces`, reads `/v1/workspaces`
- `documents`, emits `gladly.documents`, reads `/v1/documents`
- `audit_events`, emits `gladly.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/gladly ./internal/sourceprojection -count=1`
- `make catalog-check`
