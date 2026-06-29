# Stigg

Generated Source Runtime SDK scaffold for `stigg`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/stigg`
- Health endpoint: `/source-runtimes/health?source_id=stigg`
- Source health receipt: `sources/stigg/source_health_receipt.json`
- EvidenceCAS reference kind: `stigg.evidence_cas_reference`

## Families

- `alerts`, emits `stigg.alerts`, reads `/v1/alerts`
- `incidents`, emits `stigg.incidents`, reads `/v1/incidents`
- `monitors`, emits `stigg.monitors`, reads `/v1/monitors`
- `dashboards`, emits `stigg.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `stigg.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/stigg ./internal/sourceprojection -count=1`
- `make catalog-check`
