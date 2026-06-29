# Intercom

Generated Source Runtime SDK scaffold for `intercom`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/intercom`
- Health endpoint: `/source-runtimes/health?source_id=intercom`
- Source health receipt: `sources/intercom/source_health_receipt.json`
- EvidenceCAS reference kind: `intercom.evidence_cas_reference`

## Families

- `users`, emits `intercom.users`, reads `/v1/users`
- `groups`, emits `intercom.groups`, reads `/v1/groups`
- `workspaces`, emits `intercom.workspaces`, reads `/v1/workspaces`
- `documents`, emits `intercom.documents`, reads `/v1/documents`
- `audit_events`, emits `intercom.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/intercom ./internal/sourceprojection -count=1`
- `make catalog-check`
