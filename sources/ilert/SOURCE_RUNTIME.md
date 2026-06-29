# Ilert

Generated Source Runtime SDK scaffold for `ilert`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ilert`
- Health endpoint: `/source-runtimes/health?source_id=ilert`
- Source health receipt: `sources/ilert/source_health_receipt.json`
- EvidenceCAS reference kind: `ilert.evidence_cas_reference`

## Families

- `alerts`, emits `ilert.alerts`, reads `/v1/alerts`
- `incidents`, emits `ilert.incidents`, reads `/v1/incidents`
- `monitors`, emits `ilert.monitors`, reads `/v1/monitors`
- `dashboards`, emits `ilert.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `ilert.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/ilert ./internal/sourceprojection -count=1`
- `make catalog-check`
