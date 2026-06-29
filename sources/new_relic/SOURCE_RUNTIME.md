# New Relic

Generated Source Runtime SDK scaffold for `new_relic`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/new_relic`
- Health endpoint: `/source-runtimes/health?source_id=new_relic`
- Source health receipt: `sources/new_relic/source_health_receipt.json`
- EvidenceCAS reference kind: `new_relic.evidence_cas_reference`

## Families

- `assets`, emits `new_relic.assets`, reads `/v1/entities`
- `findings`, emits `new_relic.findings`, reads `/v1/alerts`
- `audit_events`, emits `new_relic.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/new_relic ./internal/sourceprojection -count=1`
- `make catalog-check`
