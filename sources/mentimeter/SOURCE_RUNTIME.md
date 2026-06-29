# Mentimeter

Generated Source Runtime SDK scaffold for `mentimeter`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mentimeter`
- Health endpoint: `/source-runtimes/health?source_id=mentimeter`
- Source health receipt: `sources/mentimeter/source_health_receipt.json`
- EvidenceCAS reference kind: `mentimeter.evidence_cas_reference`

## Families

- `users`, emits `mentimeter.users`, reads `/v1/users`
- `groups`, emits `mentimeter.groups`, reads `/v1/groups`
- `workspaces`, emits `mentimeter.workspaces`, reads `/v1/workspaces`
- `documents`, emits `mentimeter.documents`, reads `/v1/documents`
- `audit_events`, emits `mentimeter.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/mentimeter ./internal/sourceprojection -count=1`
- `make catalog-check`
