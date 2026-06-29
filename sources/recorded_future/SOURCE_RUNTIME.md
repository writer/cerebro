# Recorded Future

Generated Source Runtime SDK scaffold for `recorded_future`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/recorded_future`
- Health endpoint: `/source-runtimes/health?source_id=recorded_future`
- Source health receipt: `sources/recorded_future/source_health_receipt.json`
- EvidenceCAS reference kind: `recorded_future.evidence_cas_reference`

## Families

- `assets`, emits `recorded_future.assets`, reads `/v1/assets`
- `findings`, emits `recorded_future.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `recorded_future.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/recorded_future ./internal/sourceprojection -count=1`
- `make catalog-check`
