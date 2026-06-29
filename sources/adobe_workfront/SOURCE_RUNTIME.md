# Adobe Workfront

Generated Source Runtime SDK scaffold for `adobe_workfront`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/adobe_workfront`
- Health endpoint: `/source-runtimes/health?source_id=adobe_workfront`
- Source health receipt: `sources/adobe_workfront/source_health_receipt.json`
- EvidenceCAS reference kind: `adobe_workfront.evidence_cas_reference`

## Families

- `users`, emits `adobe_workfront.users`, reads `/v1/users`
- `groups`, emits `adobe_workfront.groups`, reads `/v1/groups`
- `workspaces`, emits `adobe_workfront.workspaces`, reads `/v1/workspaces`
- `documents`, emits `adobe_workfront.documents`, reads `/v1/documents`
- `audit_events`, emits `adobe_workfront.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/adobe_workfront ./internal/sourceprojection -count=1`
- `make catalog-check`
