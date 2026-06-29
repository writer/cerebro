# Observe Platform

Generated Source Runtime SDK scaffold for `observe_platform`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/observe_platform`
- Health endpoint: `/source-runtimes/health?source_id=observe_platform`
- Source health receipt: `sources/observe_platform/source_health_receipt.json`
- EvidenceCAS reference kind: `observe_platform.evidence_cas_reference`

## Families

- `alerts`, emits `observe_platform.alerts`, reads `/v1/alerts`
- `incidents`, emits `observe_platform.incidents`, reads `/v1/incidents`
- `monitors`, emits `observe_platform.monitors`, reads `/v1/monitors`
- `dashboards`, emits `observe_platform.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `observe_platform.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/observe_platform ./internal/sourceprojection -count=1`
- `make catalog-check`
