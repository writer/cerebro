# Better Stack

Generated Source Runtime SDK scaffold for `better_stack`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/better_stack`
- Health endpoint: `/source-runtimes/health?source_id=better_stack`
- Source health receipt: `sources/better_stack/source_health_receipt.json`
- EvidenceCAS reference kind: `better_stack.evidence_cas_reference`

## Families

- `alerts`, emits `better_stack.alerts`, reads `/v1/alerts`
- `incidents`, emits `better_stack.incidents`, reads `/v1/incidents`
- `monitors`, emits `better_stack.monitors`, reads `/v1/monitors`
- `dashboards`, emits `better_stack.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `better_stack.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/better_stack ./internal/sourceprojection -count=1`
- `make catalog-check`
