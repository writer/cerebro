# Monday.com

Generated Source Runtime SDK scaffold for `monday_com`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/monday_com`
- Health endpoint: `/source-runtimes/health?source_id=monday_com`
- Source health receipt: `sources/monday_com/source_health_receipt.json`
- EvidenceCAS reference kind: `monday_com.evidence_cas_reference`

## Families

- `users`, emits `monday_com.users`, reads `/v1/users`
- `projects`, emits `monday_com.projects`, reads `/v1/projects`
- `audit_events`, emits `monday_com.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/monday_com ./internal/sourceprojection -count=1`
- `make catalog-check`
