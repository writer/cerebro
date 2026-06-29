# Rollbar

Generated Source Runtime SDK scaffold for `rollbar`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/rollbar`
- Health endpoint: `/source-runtimes/health?source_id=rollbar`
- Source health receipt: `sources/rollbar/source_health_receipt.json`
- EvidenceCAS reference kind: `rollbar.evidence_cas_reference`

## Families

- `alerts`, emits `rollbar.alerts`, reads `/v1/alerts`
- `incidents`, emits `rollbar.incidents`, reads `/v1/incidents`
- `monitors`, emits `rollbar.monitors`, reads `/v1/monitors`
- `dashboards`, emits `rollbar.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `rollbar.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/rollbar ./internal/sourceprojection -count=1`
- `make catalog-check`
