# Google SecOps/Chronicle

Generated Source Runtime SDK scaffold for `google_secops_chronicle`.

## Runtime input

- Source type: `json_api`
- Auth model: `jwt`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/google_secops_chronicle`
- Health endpoint: `/source-runtimes/health?source_id=google_secops_chronicle`
- Source health receipt: `sources/google_secops_chronicle/source_health_receipt.json`
- EvidenceCAS reference kind: `google_secops_chronicle.evidence_cas_reference`

## Families

- `audit_events`, emits `google_secops_chronicle.audit_events`, reads `/v1/events`
- `findings`, emits `google_secops_chronicle.findings`, reads `/v1/detections`
- `assets`, emits `google_secops_chronicle.assets`, reads `/v1/assets`

## Tests

- `go test ./sources/google_secops_chronicle ./internal/sourceprojection -count=1`
- `make catalog-check`
