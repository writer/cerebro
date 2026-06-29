# Wiz

Generated Source Runtime SDK scaffold for `wiz`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/wiz`
- Health endpoint: `/source-runtimes/health?source_id=wiz`
- Source health receipt: `sources/wiz/source_health_receipt.json`
- EvidenceCAS reference kind: `wiz.evidence_cas_reference`

## Families

- `assets`, emits `wiz.assets`, reads `/v1/assets`
- `findings`, emits `wiz.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `wiz.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/wiz ./internal/sourceprojection -count=1`
- `make catalog-check`
