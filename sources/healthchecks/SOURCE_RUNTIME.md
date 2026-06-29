# Healthchecks

Generated Source Runtime SDK scaffold for `healthchecks`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/healthchecks`
- Health endpoint: `/source-runtimes/health?source_id=healthchecks`
- Source health receipt: `sources/healthchecks/source_health_receipt.json`
- EvidenceCAS reference kind: `healthchecks.evidence_cas_reference`

## Families

- `alerts`, emits `healthchecks.alerts`, reads `/v1/alerts`
- `incidents`, emits `healthchecks.incidents`, reads `/v1/incidents`
- `monitors`, emits `healthchecks.monitors`, reads `/v1/monitors`
- `dashboards`, emits `healthchecks.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `healthchecks.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/healthchecks ./internal/sourceprojection -count=1`
- `make catalog-check`
