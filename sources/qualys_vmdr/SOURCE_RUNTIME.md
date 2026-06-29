# Qualys VMDR

Generated Source Runtime SDK scaffold for `qualys_vmdr`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/qualys_vmdr`
- Health endpoint: `/source-runtimes/health?source_id=qualys_vmdr`
- Source health receipt: `sources/qualys_vmdr/source_health_receipt.json`
- EvidenceCAS reference kind: `qualys_vmdr.evidence_cas_reference`

## Families

- `assets`, emits `qualys_vmdr.assets`, reads `/v1/assets`
- `findings`, emits `qualys_vmdr.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `qualys_vmdr.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/qualys_vmdr ./internal/sourceprojection -count=1`
- `make catalog-check`
