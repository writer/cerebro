# Mend.io

Generated Source Runtime SDK scaffold for `mend_io`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mend_io`
- Health endpoint: `/source-runtimes/health?source_id=mend_io`
- Source health receipt: `sources/mend_io/source_health_receipt.json`
- EvidenceCAS reference kind: `mend_io.evidence_cas_reference`

## Families

- `assets`, emits `mend_io.assets`, reads `/v1/assets`
- `findings`, emits `mend_io.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `mend_io.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/mend_io ./internal/sourceprojection -count=1`
- `make catalog-check`
