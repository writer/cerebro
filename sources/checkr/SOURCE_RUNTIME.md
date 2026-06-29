# Checkr

Generated Source Runtime SDK scaffold for `checkr`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/checkr`
- Health endpoint: `/source-runtimes/health?source_id=checkr`
- Source health receipt: `sources/checkr/source_health_receipt.json`
- EvidenceCAS reference kind: `checkr.evidence_cas_reference`

## Families

- `users`, emits `checkr.users`, reads `/v1/users`
- `candidates`, emits `checkr.candidates`, reads `/v1/candidates`
- `background_checks`, emits `checkr.background_checks`, reads `/v1/reports`

## Tests

- `go test ./sources/checkr ./internal/sourceprojection -count=1`
- `make catalog-check`
