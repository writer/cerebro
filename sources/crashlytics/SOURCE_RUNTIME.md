# Crashlytics

Generated Source Runtime SDK scaffold for `crashlytics`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/crashlytics`
- Health endpoint: `/source-runtimes/health?source_id=crashlytics`
- Source health receipt: `sources/crashlytics/source_health_receipt.json`
- EvidenceCAS reference kind: `crashlytics.evidence_cas_reference`

## Families

- `alerts`, emits `crashlytics.alerts`, reads `/v1/alerts`
- `incidents`, emits `crashlytics.incidents`, reads `/v1/incidents`
- `monitors`, emits `crashlytics.monitors`, reads `/v1/monitors`
- `dashboards`, emits `crashlytics.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `crashlytics.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/crashlytics ./internal/sourceprojection -count=1`
- `make catalog-check`
