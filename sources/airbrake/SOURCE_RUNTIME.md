# Airbrake

Generated Source Runtime SDK scaffold for `airbrake`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/airbrake`
- Health endpoint: `/source-runtimes/health?source_id=airbrake`
- Source health receipt: `sources/airbrake/source_health_receipt.json`
- EvidenceCAS reference kind: `airbrake.evidence_cas_reference`

## Families

- `alerts`, emits `airbrake.alerts`, reads `/v1/alerts`
- `incidents`, emits `airbrake.incidents`, reads `/v1/incidents`
- `monitors`, emits `airbrake.monitors`, reads `/v1/monitors`
- `dashboards`, emits `airbrake.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `airbrake.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/airbrake ./internal/sourceprojection -count=1`
- `make catalog-check`
