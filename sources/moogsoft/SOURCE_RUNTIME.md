# Moogsoft

Generated Source Runtime SDK scaffold for `moogsoft`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/moogsoft`
- Health endpoint: `/source-runtimes/health?source_id=moogsoft`
- Source health receipt: `sources/moogsoft/source_health_receipt.json`
- EvidenceCAS reference kind: `moogsoft.evidence_cas_reference`

## Families

- `alerts`, emits `moogsoft.alerts`, reads `/v1/alerts`
- `incidents`, emits `moogsoft.incidents`, reads `/v1/incidents`
- `monitors`, emits `moogsoft.monitors`, reads `/v1/monitors`
- `dashboards`, emits `moogsoft.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `moogsoft.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/moogsoft ./internal/sourceprojection -count=1`
- `make catalog-check`
