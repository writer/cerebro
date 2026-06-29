# Highlight

Generated Source Runtime SDK scaffold for `highlight`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/highlight`
- Health endpoint: `/source-runtimes/health?source_id=highlight`
- Source health receipt: `sources/highlight/source_health_receipt.json`
- EvidenceCAS reference kind: `highlight.evidence_cas_reference`

## Families

- `alerts`, emits `highlight.alerts`, reads `/v1/alerts`
- `incidents`, emits `highlight.incidents`, reads `/v1/incidents`
- `monitors`, emits `highlight.monitors`, reads `/v1/monitors`
- `dashboards`, emits `highlight.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `highlight.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/highlight ./internal/sourceprojection -count=1`
- `make catalog-check`
