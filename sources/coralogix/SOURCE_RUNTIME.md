# Coralogix

Generated Source Runtime SDK scaffold for `coralogix`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/coralogix`
- Health endpoint: `/source-runtimes/health?source_id=coralogix`
- Source health receipt: `sources/coralogix/source_health_receipt.json`
- EvidenceCAS reference kind: `coralogix.evidence_cas_reference`

## Families

- `alerts`, emits `coralogix.alerts`, reads `/v1/alerts`
- `incidents`, emits `coralogix.incidents`, reads `/v1/incidents`
- `monitors`, emits `coralogix.monitors`, reads `/v1/monitors`
- `dashboards`, emits `coralogix.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `coralogix.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/coralogix ./internal/sourceprojection -count=1`
- `make catalog-check`
