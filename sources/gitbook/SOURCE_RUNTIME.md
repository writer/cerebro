# Gitbook

Generated Source Runtime SDK scaffold for `gitbook`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gitbook`
- Health endpoint: `/source-runtimes/health?source_id=gitbook`
- Source health receipt: `sources/gitbook/source_health_receipt.json`
- EvidenceCAS reference kind: `gitbook.evidence_cas_reference`

## Families

- `users`, emits `gitbook.users`, reads `/v1/users`
- `groups`, emits `gitbook.groups`, reads `/v1/groups`
- `workspaces`, emits `gitbook.workspaces`, reads `/v1/workspaces`
- `documents`, emits `gitbook.documents`, reads `/v1/documents`
- `audit_events`, emits `gitbook.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/gitbook ./internal/sourceprojection -count=1`
- `make catalog-check`
