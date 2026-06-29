# Splunk Cloud

Generated Source Runtime SDK scaffold for `splunk_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/splunk_cloud`
- Health endpoint: `/source-runtimes/health?source_id=splunk_cloud`
- Source health receipt: `sources/splunk_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `splunk_cloud.evidence_cas_reference`

## Families

- `audit_events`, emits `splunk_cloud.audit_events`, reads `/v1/events`
- `findings`, emits `splunk_cloud.findings`, reads `/v1/detections`
- `assets`, emits `splunk_cloud.assets`, reads `/v1/assets`

## Tests

- `go test ./sources/splunk_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
