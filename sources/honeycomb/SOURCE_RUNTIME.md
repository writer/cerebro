# Honeycomb

Generated Source Runtime SDK scaffold for `honeycomb`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/honeycomb`
- Health endpoint: `/source-runtimes/health?source_id=honeycomb`
- Source health receipt: `sources/honeycomb/source_health_receipt.json`
- EvidenceCAS reference kind: `honeycomb.evidence_cas_reference`

## Families

- `alerts`, emits `honeycomb.alerts`, reads `/v1/alerts`
- `incidents`, emits `honeycomb.incidents`, reads `/v1/incidents`
- `monitors`, emits `honeycomb.monitors`, reads `/v1/monitors`
- `dashboards`, emits `honeycomb.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `honeycomb.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/honeycomb ./internal/sourceprojection -count=1`
- `make catalog-check`
