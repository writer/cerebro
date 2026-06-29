# Lightstep

Generated Source Runtime SDK scaffold for `lightstep`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/lightstep`
- Health endpoint: `/source-runtimes/health?source_id=lightstep`
- Source health receipt: `sources/lightstep/source_health_receipt.json`
- EvidenceCAS reference kind: `lightstep.evidence_cas_reference`

## Families

- `alerts`, emits `lightstep.alerts`, reads `/v1/alerts`
- `incidents`, emits `lightstep.incidents`, reads `/v1/incidents`
- `monitors`, emits `lightstep.monitors`, reads `/v1/monitors`
- `dashboards`, emits `lightstep.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `lightstep.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/lightstep ./internal/sourceprojection -count=1`
- `make catalog-check`
