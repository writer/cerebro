# Airtable

Generated Source Runtime SDK scaffold for `airtable`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/airtable`
- Health endpoint: `/source-runtimes/health?source_id=airtable`
- Source health receipt: `sources/airtable/source_health_receipt.json`
- EvidenceCAS reference kind: `airtable.evidence_cas_reference`

## Families

- `users`, emits `airtable.users`, reads `/v1/users`
- `projects`, emits `airtable.projects`, reads `/v1/projects`
- `audit_events`, emits `airtable.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/airtable ./internal/sourceprojection -count=1`
- `make catalog-check`
