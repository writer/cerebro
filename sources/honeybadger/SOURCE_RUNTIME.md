# Honeybadger

Generated Source Runtime SDK scaffold for `honeybadger`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/honeybadger`
- Health endpoint: `/source-runtimes/health?source_id=honeybadger`
- Source health receipt: `sources/honeybadger/source_health_receipt.json`
- EvidenceCAS reference kind: `honeybadger.evidence_cas_reference`

## Families

- `alerts`, emits `honeybadger.alerts`, reads `/v1/alerts`
- `incidents`, emits `honeybadger.incidents`, reads `/v1/incidents`
- `monitors`, emits `honeybadger.monitors`, reads `/v1/monitors`
- `dashboards`, emits `honeybadger.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `honeybadger.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/honeybadger ./internal/sourceprojection -count=1`
- `make catalog-check`
