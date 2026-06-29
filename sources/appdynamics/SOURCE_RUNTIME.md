# Appdynamics

Generated Source Runtime SDK scaffold for `appdynamics`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/appdynamics`
- Health endpoint: `/source-runtimes/health?source_id=appdynamics`
- Source health receipt: `sources/appdynamics/source_health_receipt.json`
- EvidenceCAS reference kind: `appdynamics.evidence_cas_reference`

## Families

- `alerts`, emits `appdynamics.alerts`, reads `/v1/alerts`
- `incidents`, emits `appdynamics.incidents`, reads `/v1/incidents`
- `monitors`, emits `appdynamics.monitors`, reads `/v1/monitors`
- `dashboards`, emits `appdynamics.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `appdynamics.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/appdynamics ./internal/sourceprojection -count=1`
- `make catalog-check`
