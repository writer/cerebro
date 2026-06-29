# Journy.io

Generated Source Runtime SDK scaffold for `journy_io`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/journy_io`
- Health endpoint: `/source-runtimes/health?source_id=journy_io`
- Source health receipt: `sources/journy_io/source_health_receipt.json`
- EvidenceCAS reference kind: `journy_io.evidence_cas_reference`

## Families

- `event`, emits `journy_io.event`, reads `/events`
- `account`, emits `journy_io.account`, reads `/properties/accounts`
- `segments_account`, emits `journy_io.segments_account`, reads `/segments/accounts`
- `user`, emits `journy_io.user`, reads `/properties/users`
- `segments_user`, emits `journy_io.segments_user`, reads `/segments/users`

## Tests

- `go test ./sources/journy_io ./internal/sourceprojection -count=1`
- `make catalog-check`
