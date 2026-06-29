# Thousandeyes

Generated Source Runtime SDK scaffold for `thousandeyes`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/thousandeyes`
- Health endpoint: `/source-runtimes/health?source_id=thousandeyes`
- Source health receipt: `sources/thousandeyes/source_health_receipt.json`
- EvidenceCAS reference kind: `thousandeyes.evidence_cas_reference`

## Families

- `alerts`, emits `thousandeyes.alerts`, reads `/v1/alerts`
- `incidents`, emits `thousandeyes.incidents`, reads `/v1/incidents`
- `monitors`, emits `thousandeyes.monitors`, reads `/v1/monitors`
- `dashboards`, emits `thousandeyes.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `thousandeyes.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/thousandeyes ./internal/sourceprojection -count=1`
- `make catalog-check`
