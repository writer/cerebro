# Checkmarx One

Generated Source Runtime SDK scaffold for `checkmarx_one`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/checkmarx_one`
- Health endpoint: `/source-runtimes/health?source_id=checkmarx_one`
- Source health receipt: `sources/checkmarx_one/source_health_receipt.json`
- EvidenceCAS reference kind: `checkmarx_one.evidence_cas_reference`

## Families

- `assets`, emits `checkmarx_one.assets`, reads `/v1/assets`
- `findings`, emits `checkmarx_one.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `checkmarx_one.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/checkmarx_one ./internal/sourceprojection -count=1`
- `make catalog-check`
