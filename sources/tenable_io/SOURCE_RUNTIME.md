# Tenable.io

Generated Source Runtime SDK scaffold for `tenable_io`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/tenable_io`
- Health endpoint: `/source-runtimes/health?source_id=tenable_io`
- Source health receipt: `sources/tenable_io/source_health_receipt.json`
- EvidenceCAS reference kind: `tenable_io.evidence_cas_reference`

## Families

- `assets`, emits `tenable_io.assets`, reads `/v1/assets`
- `findings`, emits `tenable_io.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `tenable_io.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/tenable_io ./internal/sourceprojection -count=1`
- `make catalog-check`
