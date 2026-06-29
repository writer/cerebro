# Veracode

Generated Source Runtime SDK scaffold for `veracode`.

## Runtime input

- Source type: `json_api`
- Auth model: `signature`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/veracode`
- Health endpoint: `/source-runtimes/health?source_id=veracode`
- Source health receipt: `sources/veracode/source_health_receipt.json`
- EvidenceCAS reference kind: `veracode.evidence_cas_reference`

## Families

- `assets`, emits `veracode.assets`, reads `/v1/assets`
- `findings`, emits `veracode.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `veracode.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/veracode ./internal/sourceprojection -count=1`
- `make catalog-check`
