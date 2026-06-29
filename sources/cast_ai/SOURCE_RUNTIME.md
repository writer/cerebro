# Cast Ai

Generated Source Runtime SDK scaffold for `cast_ai`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cast_ai`
- Health endpoint: `/source-runtimes/health?source_id=cast_ai`
- Source health receipt: `sources/cast_ai/source_health_receipt.json`
- EvidenceCAS reference kind: `cast_ai.evidence_cas_reference`

## Families

- `alerts`, emits `cast_ai.alerts`, reads `/v1/alerts`
- `incidents`, emits `cast_ai.incidents`, reads `/v1/incidents`
- `monitors`, emits `cast_ai.monitors`, reads `/v1/monitors`
- `dashboards`, emits `cast_ai.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `cast_ai.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cast_ai ./internal/sourceprojection -count=1`
- `make catalog-check`
