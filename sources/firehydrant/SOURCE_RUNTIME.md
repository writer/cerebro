# Firehydrant

Generated Source Runtime SDK scaffold for `firehydrant`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/firehydrant`
- Health endpoint: `/source-runtimes/health?source_id=firehydrant`
- Source health receipt: `sources/firehydrant/source_health_receipt.json`
- EvidenceCAS reference kind: `firehydrant.evidence_cas_reference`

## Families

- `alerts`, emits `firehydrant.alerts`, reads `/v1/alerts`
- `incidents`, emits `firehydrant.incidents`, reads `/v1/incidents`
- `monitors`, emits `firehydrant.monitors`, reads `/v1/monitors`
- `dashboards`, emits `firehydrant.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `firehydrant.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/firehydrant ./internal/sourceprojection -count=1`
- `make catalog-check`
