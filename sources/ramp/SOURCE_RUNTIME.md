# Ramp

Generated Source Runtime SDK scaffold for `ramp`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ramp`
- Health endpoint: `/source-runtimes/health?source_id=ramp`
- Source health receipt: `sources/ramp/source_health_receipt.json`
- EvidenceCAS reference kind: `ramp.evidence_cas_reference`

## Families

- `users`, emits `ramp.users`, reads `/users`
- `cards`, emits `ramp.cards`, reads `/cards`
- `transactions`, emits `ramp.transactions`, reads `/transactions`

## Tests

- `go test ./sources/ramp ./internal/sourceprojection -count=1`
- `make catalog-check`
