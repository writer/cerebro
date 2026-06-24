# Asana

Generated Source Runtime SDK scaffold for `asana`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/asana`
- Health endpoint: `/source-runtimes/health?source_id=asana`
- Source health receipt: `sources/asana/source_health_receipt.json`
- EvidenceCAS reference kind: `asana.evidence_cas_reference`

## Families

- `users`, emits `asana.users`, reads `/v1/users`
- `projects`, emits `asana.projects`, reads `/v1/projects`
- `audit_events`, emits `asana.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/asana ./internal/sourceprojection -count=1`
- `make catalog-check`
