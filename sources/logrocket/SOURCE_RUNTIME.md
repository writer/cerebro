# Logrocket

Generated Source Runtime SDK scaffold for `logrocket`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/logrocket`
- Health endpoint: `/source-runtimes/health?source_id=logrocket`
- Source health receipt: `sources/logrocket/source_health_receipt.json`
- EvidenceCAS reference kind: `logrocket.evidence_cas_reference`

## Families

- `alerts`, emits `logrocket.alerts`, reads `/v1/alerts`
- `incidents`, emits `logrocket.incidents`, reads `/v1/incidents`
- `monitors`, emits `logrocket.monitors`, reads `/v1/monitors`
- `dashboards`, emits `logrocket.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `logrocket.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/logrocket ./internal/sourceprojection -count=1`
- `make catalog-check`
