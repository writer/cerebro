# Fire

Generated Source Runtime SDK scaffold for `fire`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fire`
- Health endpoint: `/source-runtimes/health?source_id=fire`
- Source health receipt: `sources/fire/source_health_receipt.json`
- EvidenceCAS reference kind: `fire.evidence_cas_reference`

## Families

- `account`, emits `fire.account`, reads `/v1/accounts`
- `aspsp`, emits `fire.aspsp`, reads `/v1/aspsps`
- `user`, emits `fire.user`, reads `/v1/users`
- `batche`, emits `fire.batche`, reads `/v1/batches`

## Tests

- `go test ./sources/fire ./internal/sourceprojection -count=1`
- `make catalog-check`
