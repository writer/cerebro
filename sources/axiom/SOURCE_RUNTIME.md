# Axiom

Generated Source Runtime SDK scaffold for `axiom`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/axiom`
- Health endpoint: `/source-runtimes/health?source_id=axiom`
- Source health receipt: `sources/axiom/source_health_receipt.json`
- EvidenceCAS reference kind: `axiom.evidence_cas_reference`

## Families

- `alerts`, emits `axiom.alerts`, reads `/v1/alerts`
- `incidents`, emits `axiom.incidents`, reads `/v1/incidents`
- `monitors`, emits `axiom.monitors`, reads `/v1/monitors`
- `dashboards`, emits `axiom.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `axiom.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/axiom ./internal/sourceprojection -count=1`
- `make catalog-check`
