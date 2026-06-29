# Logz.io

Generated Source Runtime SDK scaffold for `logz_io`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/logz_io`
- Health endpoint: `/source-runtimes/health?source_id=logz_io`
- Source health receipt: `sources/logz_io/source_health_receipt.json`
- EvidenceCAS reference kind: `logz_io.evidence_cas_reference`

## Families

- `alerts`, emits `logz_io.alerts`, reads `/v1/alerts`
- `incidents`, emits `logz_io.incidents`, reads `/v1/incidents`
- `monitors`, emits `logz_io.monitors`, reads `/v1/monitors`
- `dashboards`, emits `logz_io.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `logz_io.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/logz_io ./internal/sourceprojection -count=1`
- `make catalog-check`
