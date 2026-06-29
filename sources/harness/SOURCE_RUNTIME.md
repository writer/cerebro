# Harness

Generated Source Runtime SDK scaffold for `harness`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/harness`
- Health endpoint: `/source-runtimes/health?source_id=harness`
- Source health receipt: `sources/harness/source_health_receipt.json`
- EvidenceCAS reference kind: `harness.evidence_cas_reference`

## Families

- `pipelines`, emits `harness.pipelines`, reads `/v1/pipelines`
- `findings`, emits `harness.findings`, reads `/v1/findings`
- `audit_events`, emits `harness.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/harness ./internal/sourceprojection -count=1`
- `make catalog-check`
