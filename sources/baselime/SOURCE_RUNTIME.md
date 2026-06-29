# Baselime

Generated Source Runtime SDK scaffold for `baselime`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/baselime`
- Health endpoint: `/source-runtimes/health?source_id=baselime`
- Source health receipt: `sources/baselime/source_health_receipt.json`
- EvidenceCAS reference kind: `baselime.evidence_cas_reference`

## Families

- `alerts`, emits `baselime.alerts`, reads `/v1/alerts`
- `incidents`, emits `baselime.incidents`, reads `/v1/incidents`
- `monitors`, emits `baselime.monitors`, reads `/v1/monitors`
- `dashboards`, emits `baselime.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `baselime.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/baselime ./internal/sourceprojection -count=1`
- `make catalog-check`
