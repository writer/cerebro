# Anchore

Generated Source Runtime SDK scaffold for `anchore`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/anchore`
- Health endpoint: `/source-runtimes/health?source_id=anchore`
- Source health receipt: `sources/anchore/source_health_receipt.json`
- EvidenceCAS reference kind: `anchore.evidence_cas_reference`

## Families

- `assets`, emits `anchore.assets`, reads `/v1/assets`
- `findings`, emits `anchore.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `anchore.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/anchore ./internal/sourceprojection -count=1`
- `make catalog-check`
