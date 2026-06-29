# Last9

Generated Source Runtime SDK scaffold for `last9`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/last9`
- Health endpoint: `/source-runtimes/health?source_id=last9`
- Source health receipt: `sources/last9/source_health_receipt.json`
- EvidenceCAS reference kind: `last9.evidence_cas_reference`

## Families

- `alerts`, emits `last9.alerts`, reads `/v1/alerts`
- `incidents`, emits `last9.incidents`, reads `/v1/incidents`
- `monitors`, emits `last9.monitors`, reads `/v1/monitors`
- `dashboards`, emits `last9.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `last9.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/last9 ./internal/sourceprojection -count=1`
- `make catalog-check`
