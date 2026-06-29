# Grammarly Business

Generated Source Runtime SDK scaffold for `grammarly_business`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/grammarly_business`
- Health endpoint: `/source-runtimes/health?source_id=grammarly_business`
- Source health receipt: `sources/grammarly_business/source_health_receipt.json`
- EvidenceCAS reference kind: `grammarly_business.evidence_cas_reference`

## Families

- `users`, emits `grammarly_business.users`, reads `/v1/users`
- `groups`, emits `grammarly_business.groups`, reads `/v1/groups`
- `workspaces`, emits `grammarly_business.workspaces`, reads `/v1/workspaces`
- `documents`, emits `grammarly_business.documents`, reads `/v1/documents`
- `audit_events`, emits `grammarly_business.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/grammarly_business ./internal/sourceprojection -count=1`
- `make catalog-check`
