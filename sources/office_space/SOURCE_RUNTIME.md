# Office Space

Generated Source Runtime SDK scaffold for `office_space`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/office_space`
- Health endpoint: `/source-runtimes/health?source_id=office_space`
- Source health receipt: `sources/office_space/source_health_receipt.json`
- EvidenceCAS reference kind: `office_space.evidence_cas_reference`

## Families

- `users`, emits `office_space.users`, reads `/v1/users`
- `groups`, emits `office_space.groups`, reads `/v1/groups`
- `workspaces`, emits `office_space.workspaces`, reads `/v1/workspaces`
- `documents`, emits `office_space.documents`, reads `/v1/documents`
- `audit_events`, emits `office_space.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/office_space ./internal/sourceprojection -count=1`
- `make catalog-check`
