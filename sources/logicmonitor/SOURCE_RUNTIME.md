# Logicmonitor

Generated Source Runtime SDK scaffold for `logicmonitor`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/logicmonitor`
- Health endpoint: `/source-runtimes/health?source_id=logicmonitor`
- Source health receipt: `sources/logicmonitor/source_health_receipt.json`
- EvidenceCAS reference kind: `logicmonitor.evidence_cas_reference`

## Families

- `alerts`, emits `logicmonitor.alerts`, reads `/v1/alerts`
- `incidents`, emits `logicmonitor.incidents`, reads `/v1/incidents`
- `monitors`, emits `logicmonitor.monitors`, reads `/v1/monitors`
- `dashboards`, emits `logicmonitor.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `logicmonitor.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/logicmonitor ./internal/sourceprojection -count=1`
- `make catalog-check`
