# Mezmo

Generated Source Runtime SDK scaffold for `mezmo`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mezmo`
- Health endpoint: `/source-runtimes/health?source_id=mezmo`
- Source health receipt: `sources/mezmo/source_health_receipt.json`
- EvidenceCAS reference kind: `mezmo.evidence_cas_reference`

## Families

- `alerts`, emits `mezmo.alerts`, reads `/v1/alerts`
- `incidents`, emits `mezmo.incidents`, reads `/v1/incidents`
- `monitors`, emits `mezmo.monitors`, reads `/v1/monitors`
- `dashboards`, emits `mezmo.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `mezmo.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/mezmo ./internal/sourceprojection -count=1`
- `make catalog-check`
