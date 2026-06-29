# Sysdig Secure

Generated Source Runtime SDK scaffold for `sysdig_secure`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sysdig_secure`
- Health endpoint: `/source-runtimes/health?source_id=sysdig_secure`
- Source health receipt: `sources/sysdig_secure/source_health_receipt.json`
- EvidenceCAS reference kind: `sysdig_secure.evidence_cas_reference`

## Families

- `assets`, emits `sysdig_secure.assets`, reads `/v1/assets`
- `findings`, emits `sysdig_secure.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `sysdig_secure.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/sysdig_secure ./internal/sourceprojection -count=1`
- `make catalog-check`
