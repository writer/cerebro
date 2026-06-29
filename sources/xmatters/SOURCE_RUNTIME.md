# Xmatters

Generated Source Runtime SDK scaffold for `xmatters`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/xmatters`
- Health endpoint: `/source-runtimes/health?source_id=xmatters`
- Source health receipt: `sources/xmatters/source_health_receipt.json`
- EvidenceCAS reference kind: `xmatters.evidence_cas_reference`

## Families

- `alerts`, emits `xmatters.alerts`, reads `/v1/alerts`
- `incidents`, emits `xmatters.incidents`, reads `/v1/incidents`
- `monitors`, emits `xmatters.monitors`, reads `/v1/monitors`
- `dashboards`, emits `xmatters.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `xmatters.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/xmatters ./internal/sourceprojection -count=1`
- `make catalog-check`
