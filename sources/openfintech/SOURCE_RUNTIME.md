# OpenFinTech

Generated Source Runtime SDK scaffold for `openfintech`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/openfintech`
- Health endpoint: `/source-runtimes/health?source_id=openfintech`
- Source health receipt: `sources/openfintech/source_health_receipt.json`
- EvidenceCAS reference kind: `openfintech.evidence_cas_reference`

## Families

- `organization`, emits `openfintech.organization`, reads `/organizations`
- `bank`, emits `openfintech.bank`, reads `/banks`
- `country`, emits `openfintech.country`, reads `/countries`
- `currency`, emits `openfintech.currency`, reads `/currencies`

## Tests

- `go test ./sources/openfintech ./internal/sourceprojection -count=1`
- `make catalog-check`
