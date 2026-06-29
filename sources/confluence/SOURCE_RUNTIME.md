# Confluence

Generated Source Runtime SDK scaffold for `confluence`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/confluence`
- Health endpoint: `/source-runtimes/health?source_id=confluence`
- Source health receipt: `sources/confluence/source_health_receipt.json`
- EvidenceCAS reference kind: `confluence.evidence_cas_reference`

## Families

- `users`, emits `confluence.users`, reads `/v1/users`
- `projects`, emits `confluence.projects`, reads `/v1/projects`
- `audit_events`, emits `confluence.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/confluence ./internal/sourceprojection -count=1`
- `make catalog-check`
