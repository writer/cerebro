# Telemetryhub

Generated Source Runtime SDK scaffold for `telemetryhub`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/telemetryhub`
- Health endpoint: `/source-runtimes/health?source_id=telemetryhub`
- Source health receipt: `sources/telemetryhub/source_health_receipt.json`
- EvidenceCAS reference kind: `telemetryhub.evidence_cas_reference`

## Families

- `alerts`, emits `telemetryhub.alerts`, reads `/v1/alerts`
- `incidents`, emits `telemetryhub.incidents`, reads `/v1/incidents`
- `monitors`, emits `telemetryhub.monitors`, reads `/v1/monitors`
- `dashboards`, emits `telemetryhub.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `telemetryhub.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/telemetryhub ./internal/sourceprojection -count=1`
- `make catalog-check`
