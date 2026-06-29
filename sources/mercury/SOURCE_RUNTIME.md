# Mercury

Generated Source Runtime SDK scaffold for `mercury`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mercury`
- Health endpoint: `/source-runtimes/health?source_id=mercury`
- Source health receipt: `sources/mercury/source_health_receipt.json`
- EvidenceCAS reference kind: `mercury.evidence_cas_reference`

## Families

- `accounts`, emits `mercury.accounts`, reads `/v1/accounts`
- `transactions`, emits `mercury.transactions`, reads `/v1/transactions`
- `users`, emits `mercury.users`, reads `/v1/users`

## Tests

- `go test ./sources/mercury ./internal/sourceprojection -count=1`
- `make catalog-check`
