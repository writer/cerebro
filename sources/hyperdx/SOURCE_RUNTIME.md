# Hyperdx

Generated Source Runtime SDK scaffold for `hyperdx`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hyperdx`
- Health endpoint: `/source-runtimes/health?source_id=hyperdx`
- Source health receipt: `sources/hyperdx/source_health_receipt.json`
- EvidenceCAS reference kind: `hyperdx.evidence_cas_reference`

## Families

- `alerts`, emits `hyperdx.alerts`, reads `/v1/alerts`
- `incidents`, emits `hyperdx.incidents`, reads `/v1/incidents`
- `monitors`, emits `hyperdx.monitors`, reads `/v1/monitors`
- `dashboards`, emits `hyperdx.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `hyperdx.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/hyperdx ./internal/sourceprojection -count=1`
- `make catalog-check`
