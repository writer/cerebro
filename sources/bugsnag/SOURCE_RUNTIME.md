# Bugsnag

Generated Source Runtime SDK scaffold for `bugsnag`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bugsnag`
- Health endpoint: `/source-runtimes/health?source_id=bugsnag`
- Source health receipt: `sources/bugsnag/source_health_receipt.json`
- EvidenceCAS reference kind: `bugsnag.evidence_cas_reference`

## Families

- `projects`, emits `bugsnag.projects`, reads `/projects`
- `errors`, emits `bugsnag.errors`, reads `/errors`
- `audit_events`, emits `bugsnag.audit_events`, reads `/audit-events`

## Tests

- `go test ./sources/bugsnag ./internal/sourceprojection -count=1`
- `make catalog-check`
