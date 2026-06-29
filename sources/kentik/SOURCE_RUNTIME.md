# Kentik

Generated Source Runtime SDK scaffold for `kentik`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/kentik`
- Health endpoint: `/source-runtimes/health?source_id=kentik`
- Source health receipt: `sources/kentik/source_health_receipt.json`
- EvidenceCAS reference kind: `kentik.evidence_cas_reference`

## Families

- `alerts`, emits `kentik.alerts`, reads `/v1/alerts`
- `incidents`, emits `kentik.incidents`, reads `/v1/incidents`
- `monitors`, emits `kentik.monitors`, reads `/v1/monitors`
- `dashboards`, emits `kentik.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `kentik.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/kentik ./internal/sourceprojection -count=1`
- `make catalog-check`
