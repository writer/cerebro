# Statuscake

Generated Source Runtime SDK scaffold for `statuscake`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/statuscake`
- Health endpoint: `/source-runtimes/health?source_id=statuscake`
- Source health receipt: `sources/statuscake/source_health_receipt.json`
- EvidenceCAS reference kind: `statuscake.evidence_cas_reference`

## Families

- `alerts`, emits `statuscake.alerts`, reads `/v1/alerts`
- `incidents`, emits `statuscake.incidents`, reads `/v1/incidents`
- `monitors`, emits `statuscake.monitors`, reads `/v1/monitors`
- `dashboards`, emits `statuscake.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `statuscake.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/statuscake ./internal/sourceprojection -count=1`
- `make catalog-check`
