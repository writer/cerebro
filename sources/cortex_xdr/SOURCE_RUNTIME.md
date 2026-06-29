# Cortex XDR

Generated Source Runtime SDK scaffold for `cortex_xdr`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cortex_xdr`
- Health endpoint: `/source-runtimes/health?source_id=cortex_xdr`
- Source health receipt: `sources/cortex_xdr/source_health_receipt.json`
- EvidenceCAS reference kind: `cortex_xdr.evidence_cas_reference`

## Families

- `assets`, emits `cortex_xdr.assets`, reads `/v1/assets`
- `findings`, emits `cortex_xdr.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `cortex_xdr.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/cortex_xdr ./internal/sourceprojection -count=1`
- `make catalog-check`
