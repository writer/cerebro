# Rapid7 InsightVM

Generated Source Runtime SDK scaffold for `rapid7_insightvm`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/rapid7_insightvm`
- Health endpoint: `/source-runtimes/health?source_id=rapid7_insightvm`
- Source health receipt: `sources/rapid7_insightvm/source_health_receipt.json`
- EvidenceCAS reference kind: `rapid7_insightvm.evidence_cas_reference`

## Families

- `assets`, emits `rapid7_insightvm.assets`, reads `/v1/assets`
- `findings`, emits `rapid7_insightvm.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `rapid7_insightvm.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/rapid7_insightvm ./internal/sourceprojection -count=1`
- `make catalog-check`
