# Groundcover

Generated Source Runtime SDK scaffold for `groundcover`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/groundcover`
- Health endpoint: `/source-runtimes/health?source_id=groundcover`
- Source health receipt: `sources/groundcover/source_health_receipt.json`
- EvidenceCAS reference kind: `groundcover.evidence_cas_reference`

## Families

- `alerts`, emits `groundcover.alerts`, reads `/v1/alerts`
- `incidents`, emits `groundcover.incidents`, reads `/v1/incidents`
- `monitors`, emits `groundcover.monitors`, reads `/v1/monitors`
- `dashboards`, emits `groundcover.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `groundcover.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/groundcover ./internal/sourceprojection -count=1`
- `make catalog-check`
