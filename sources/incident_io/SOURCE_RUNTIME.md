# incident.io

Generated Source Runtime SDK scaffold for `incident_io`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/incident_io`
- Health endpoint: `/source-runtimes/health?source_id=incident_io`
- Source health receipt: `sources/incident_io/source_health_receipt.json`
- EvidenceCAS reference kind: `incident_io.evidence_cas_reference`

## Families

- `alerts`, emits `incident_io.alerts`, reads `/v1/alerts`
- `incidents`, emits `incident_io.incidents`, reads `/v1/incidents`
- `monitors`, emits `incident_io.monitors`, reads `/v1/monitors`
- `dashboards`, emits `incident_io.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `incident_io.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/incident_io ./internal/sourceprojection -count=1`
- `make catalog-check`
