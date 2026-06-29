# Creately

Generated Source Runtime SDK scaffold for `creately`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/creately`
- Health endpoint: `/source-runtimes/health?source_id=creately`
- Source health receipt: `sources/creately/source_health_receipt.json`
- EvidenceCAS reference kind: `creately.evidence_cas_reference`

## Families

- `users`, emits `creately.users`, reads `/v1/users`
- `groups`, emits `creately.groups`, reads `/v1/groups`
- `workspaces`, emits `creately.workspaces`, reads `/v1/workspaces`
- `documents`, emits `creately.documents`, reads `/v1/documents`
- `audit_events`, emits `creately.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/creately ./internal/sourceprojection -count=1`
- `make catalog-check`
