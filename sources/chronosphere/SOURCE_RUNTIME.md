# Chronosphere

Generated Source Runtime SDK scaffold for `chronosphere`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/chronosphere`
- Health endpoint: `/source-runtimes/health?source_id=chronosphere`
- Source health receipt: `sources/chronosphere/source_health_receipt.json`
- EvidenceCAS reference kind: `chronosphere.evidence_cas_reference`

## Families

- `alerts`, emits `chronosphere.alerts`, reads `/v1/alerts`
- `incidents`, emits `chronosphere.incidents`, reads `/v1/incidents`
- `monitors`, emits `chronosphere.monitors`, reads `/v1/monitors`
- `dashboards`, emits `chronosphere.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `chronosphere.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/chronosphere ./internal/sourceprojection -count=1`
- `make catalog-check`
