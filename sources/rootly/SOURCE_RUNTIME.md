# Rootly

Generated Source Runtime SDK scaffold for `rootly`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/rootly`
- Health endpoint: `/source-runtimes/health?source_id=rootly`
- Source health receipt: `sources/rootly/source_health_receipt.json`
- EvidenceCAS reference kind: `rootly.evidence_cas_reference`

## Families

- `alerts`, emits `rootly.alerts`, reads `/v1/alerts`
- `incidents`, emits `rootly.incidents`, reads `/v1/incidents`
- `monitors`, emits `rootly.monitors`, reads `/v1/monitors`
- `dashboards`, emits `rootly.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `rootly.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/rootly ./internal/sourceprojection -count=1`
- `make catalog-check`
