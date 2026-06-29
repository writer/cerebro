# Lacework

Generated Source Runtime SDK scaffold for `lacework`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/lacework`
- Health endpoint: `/source-runtimes/health?source_id=lacework`
- Source health receipt: `sources/lacework/source_health_receipt.json`
- EvidenceCAS reference kind: `lacework.evidence_cas_reference`

## Families

- `assets`, emits `lacework.assets`, reads `/v1/assets`
- `findings`, emits `lacework.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `lacework.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/lacework ./internal/sourceprojection -count=1`
- `make catalog-check`
