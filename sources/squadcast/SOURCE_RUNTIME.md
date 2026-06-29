# Squadcast

Generated Source Runtime SDK scaffold for `squadcast`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/squadcast`
- Health endpoint: `/source-runtimes/health?source_id=squadcast`
- Source health receipt: `sources/squadcast/source_health_receipt.json`
- EvidenceCAS reference kind: `squadcast.evidence_cas_reference`

## Families

- `alerts`, emits `squadcast.alerts`, reads `/v1/alerts`
- `incidents`, emits `squadcast.incidents`, reads `/v1/incidents`
- `monitors`, emits `squadcast.monitors`, reads `/v1/monitors`
- `dashboards`, emits `squadcast.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `squadcast.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/squadcast ./internal/sourceprojection -count=1`
- `make catalog-check`
