# Codefresh

Generated Source Runtime SDK scaffold for `codefresh`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/codefresh`
- Health endpoint: `/source-runtimes/health?source_id=codefresh`
- Source health receipt: `sources/codefresh/source_health_receipt.json`
- EvidenceCAS reference kind: `codefresh.evidence_cas_reference`

## Families

- `projects`, emits `codefresh.projects`, reads `/projects`
- `builds`, emits `codefresh.builds`, reads `/builds`
- `audit_events`, emits `codefresh.audit_events`, reads `/audit/events`

## Tests

- `go test ./sources/codefresh ./internal/sourceprojection -count=1`
- `make catalog-check`
