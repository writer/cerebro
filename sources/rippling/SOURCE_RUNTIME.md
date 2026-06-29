# Rippling

Generated Source Runtime SDK scaffold for `rippling`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/rippling`
- Health endpoint: `/source-runtimes/health?source_id=rippling`
- Source health receipt: `sources/rippling/source_health_receipt.json`
- EvidenceCAS reference kind: `rippling.evidence_cas_reference`

## Families

- `users`, emits `rippling.users`, reads `/workers`
- `devices`, emits `rippling.devices`, reads `/devices`
- `background_checks`, emits `rippling.background_checks`, reads `/background-checks`

## Tests

- `go test ./sources/rippling ./internal/sourceprojection -count=1`
- `make catalog-check`
