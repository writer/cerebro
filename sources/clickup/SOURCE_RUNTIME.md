# ClickUp

Generated Source Runtime SDK scaffold for `clickup`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/clickup`
- Health endpoint: `/source-runtimes/health?source_id=clickup`
- Source health receipt: `sources/clickup/source_health_receipt.json`
- EvidenceCAS reference kind: `clickup.evidence_cas_reference`

## Families

- `users`, emits `clickup.users`, reads `/v1/users`
- `projects`, emits `clickup.projects`, reads `/v1/projects`
- `audit_events`, emits `clickup.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/clickup ./internal/sourceprojection -count=1`
- `make catalog-check`
