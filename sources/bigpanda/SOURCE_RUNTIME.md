# Bigpanda

Generated Source Runtime SDK scaffold for `bigpanda`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bigpanda`
- Health endpoint: `/source-runtimes/health?source_id=bigpanda`
- Source health receipt: `sources/bigpanda/source_health_receipt.json`
- EvidenceCAS reference kind: `bigpanda.evidence_cas_reference`

## Families

- `alerts`, emits `bigpanda.alerts`, reads `/v1/alerts`
- `incidents`, emits `bigpanda.incidents`, reads `/v1/incidents`
- `monitors`, emits `bigpanda.monitors`, reads `/v1/monitors`
- `dashboards`, emits `bigpanda.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `bigpanda.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/bigpanda ./internal/sourceprojection -count=1`
- `make catalog-check`
