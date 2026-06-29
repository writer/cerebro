# Catchpoint

Generated Source Runtime SDK scaffold for `catchpoint`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/catchpoint`
- Health endpoint: `/source-runtimes/health?source_id=catchpoint`
- Source health receipt: `sources/catchpoint/source_health_receipt.json`
- EvidenceCAS reference kind: `catchpoint.evidence_cas_reference`

## Families

- `alerts`, emits `catchpoint.alerts`, reads `/v1/alerts`
- `incidents`, emits `catchpoint.incidents`, reads `/v1/incidents`
- `monitors`, emits `catchpoint.monitors`, reads `/v1/monitors`
- `dashboards`, emits `catchpoint.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `catchpoint.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/catchpoint ./internal/sourceprojection -count=1`
- `make catalog-check`
