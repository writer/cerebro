# Sentry

Generated Source Runtime SDK scaffold for `sentry`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sentry`
- Health endpoint: `/source-runtimes/health?source_id=sentry`
- Source health receipt: `sources/sentry/source_health_receipt.json`
- EvidenceCAS reference kind: `sentry.evidence_cas_reference`

## Families

- `assets`, emits `sentry.assets`, reads `/v1/assets`
- `findings`, emits `sentry.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `sentry.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/sentry ./internal/sourceprojection -count=1`
- `make catalog-check`
