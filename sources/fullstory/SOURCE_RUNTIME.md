# Fullstory

Generated Source Runtime SDK scaffold for `fullstory`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fullstory`
- Health endpoint: `/source-runtimes/health?source_id=fullstory`
- Source health receipt: `sources/fullstory/source_health_receipt.json`
- EvidenceCAS reference kind: `fullstory.evidence_cas_reference`

## Families

- `alerts`, emits `fullstory.alerts`, reads `/v1/alerts`
- `incidents`, emits `fullstory.incidents`, reads `/v1/incidents`
- `monitors`, emits `fullstory.monitors`, reads `/v1/monitors`
- `dashboards`, emits `fullstory.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `fullstory.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/fullstory ./internal/sourceprojection -count=1`
- `make catalog-check`
