# Uptrace

Generated Source Runtime SDK scaffold for `uptrace`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/uptrace`
- Health endpoint: `/source-runtimes/health?source_id=uptrace`
- Source health receipt: `sources/uptrace/source_health_receipt.json`
- EvidenceCAS reference kind: `uptrace.evidence_cas_reference`

## Families

- `alerts`, emits `uptrace.alerts`, reads `/v1/alerts`
- `incidents`, emits `uptrace.incidents`, reads `/v1/incidents`
- `monitors`, emits `uptrace.monitors`, reads `/v1/monitors`
- `dashboards`, emits `uptrace.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `uptrace.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/uptrace ./internal/sourceprojection -count=1`
- `make catalog-check`
