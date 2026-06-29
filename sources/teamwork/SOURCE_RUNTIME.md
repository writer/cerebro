# Teamwork

Generated Source Runtime SDK scaffold for `teamwork`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/teamwork`
- Health endpoint: `/source-runtimes/health?source_id=teamwork`
- Source health receipt: `sources/teamwork/source_health_receipt.json`
- EvidenceCAS reference kind: `teamwork.evidence_cas_reference`

## Families

- `users`, emits `teamwork.users`, reads `/v1/users`
- `groups`, emits `teamwork.groups`, reads `/v1/groups`
- `workspaces`, emits `teamwork.workspaces`, reads `/v1/workspaces`
- `documents`, emits `teamwork.documents`, reads `/v1/documents`
- `audit_events`, emits `teamwork.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/teamwork ./internal/sourceprojection -count=1`
- `make catalog-check`
