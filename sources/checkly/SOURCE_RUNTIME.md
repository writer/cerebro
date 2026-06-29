# Checkly

Generated Source Runtime SDK scaffold for `checkly`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/checkly`
- Health endpoint: `/source-runtimes/health?source_id=checkly`
- Source health receipt: `sources/checkly/source_health_receipt.json`
- EvidenceCAS reference kind: `checkly.evidence_cas_reference`

## Families

- `alerts`, emits `checkly.alerts`, reads `/v1/alerts`
- `incidents`, emits `checkly.incidents`, reads `/v1/incidents`
- `monitors`, emits `checkly.monitors`, reads `/v1/monitors`
- `dashboards`, emits `checkly.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `checkly.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/checkly ./internal/sourceprojection -count=1`
- `make catalog-check`
