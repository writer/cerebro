# Splunk Observability

Generated Source Runtime SDK scaffold for `splunk_observability`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/splunk_observability`
- Health endpoint: `/source-runtimes/health?source_id=splunk_observability`
- Source health receipt: `sources/splunk_observability/source_health_receipt.json`
- EvidenceCAS reference kind: `splunk_observability.evidence_cas_reference`

## Families

- `alerts`, emits `splunk_observability.alerts`, reads `/v1/alerts`
- `incidents`, emits `splunk_observability.incidents`, reads `/v1/incidents`
- `monitors`, emits `splunk_observability.monitors`, reads `/v1/monitors`
- `dashboards`, emits `splunk_observability.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `splunk_observability.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/splunk_observability ./internal/sourceprojection -count=1`
- `make catalog-check`
