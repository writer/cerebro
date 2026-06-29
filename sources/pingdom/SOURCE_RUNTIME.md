# Pingdom

Generated Source Runtime SDK scaffold for `pingdom`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/pingdom`
- Health endpoint: `/source-runtimes/health?source_id=pingdom`
- Source health receipt: `sources/pingdom/source_health_receipt.json`
- EvidenceCAS reference kind: `pingdom.evidence_cas_reference`

## Families

- `alerts`, emits `pingdom.alerts`, reads `/v1/alerts`
- `incidents`, emits `pingdom.incidents`, reads `/v1/incidents`
- `monitors`, emits `pingdom.monitors`, reads `/v1/monitors`
- `dashboards`, emits `pingdom.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `pingdom.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/pingdom ./internal/sourceprojection -count=1`
- `make catalog-check`
