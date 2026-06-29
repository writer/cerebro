# Dynatrace

Generated Source Runtime SDK scaffold for `dynatrace`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/dynatrace`
- Health endpoint: `/source-runtimes/health?source_id=dynatrace`
- Source health receipt: `sources/dynatrace/source_health_receipt.json`
- EvidenceCAS reference kind: `dynatrace.evidence_cas_reference`

## Families

- `alerts`, emits `dynatrace.alerts`, reads `/v1/alerts`
- `incidents`, emits `dynatrace.incidents`, reads `/v1/incidents`
- `monitors`, emits `dynatrace.monitors`, reads `/v1/monitors`
- `dashboards`, emits `dynatrace.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `dynatrace.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/dynatrace ./internal/sourceprojection -count=1`
- `make catalog-check`
