# Censys ASM

Generated Source Runtime SDK scaffold for `censys_asm`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/censys_asm`
- Health endpoint: `/source-runtimes/health?source_id=censys_asm`
- Source health receipt: `sources/censys_asm/source_health_receipt.json`
- EvidenceCAS reference kind: `censys_asm.evidence_cas_reference`

## Families

- `assets`, emits `censys_asm.assets`, reads `/v1/assets`
- `findings`, emits `censys_asm.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `censys_asm.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/censys_asm ./internal/sourceprojection -count=1`
- `make catalog-check`
