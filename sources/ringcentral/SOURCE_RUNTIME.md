# Ringcentral

Generated Source Runtime SDK scaffold for `ringcentral`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ringcentral`
- Health endpoint: `/source-runtimes/health?source_id=ringcentral`
- Source health receipt: `sources/ringcentral/source_health_receipt.json`
- EvidenceCAS reference kind: `ringcentral.evidence_cas_reference`

## Families

- `users`, emits `ringcentral.users`, reads `/v1/users`
- `groups`, emits `ringcentral.groups`, reads `/v1/groups`
- `workspaces`, emits `ringcentral.workspaces`, reads `/v1/workspaces`
- `documents`, emits `ringcentral.documents`, reads `/v1/documents`
- `audit_events`, emits `ringcentral.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/ringcentral ./internal/sourceprojection -count=1`
- `make catalog-check`
