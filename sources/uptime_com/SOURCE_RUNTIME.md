# Uptime.com

Generated Source Runtime SDK scaffold for `uptime_com`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/uptime_com`
- Health endpoint: `/source-runtimes/health?source_id=uptime_com`
- Source health receipt: `sources/uptime_com/source_health_receipt.json`
- EvidenceCAS reference kind: `uptime_com.evidence_cas_reference`

## Families

- `alerts`, emits `uptime_com.alerts`, reads `/v1/alerts`
- `incidents`, emits `uptime_com.incidents`, reads `/v1/incidents`
- `monitors`, emits `uptime_com.monitors`, reads `/v1/monitors`
- `dashboards`, emits `uptime_com.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `uptime_com.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/uptime_com ./internal/sourceprojection -count=1`
- `make catalog-check`
