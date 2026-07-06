# Apollo

Provider-verified Source Runtime SDK for `apollo`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: Apollo API key in the `x-api-key` header
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/apollo`
- Health endpoint: `/source-runtimes/health?source_id=apollo`
- Source health receipt: `sources/apollo/source_health_receipt.json`
- EvidenceCAS reference kind: `apollo.evidence_cas_reference`

## Families

- `users`, emits `apollo.users`, reads `GET /users/search`
- `accounts`, emits `apollo.accounts`, reads `POST /accounts/search`
- `contacts`, emits `apollo.contacts`, reads `POST /contacts/search`

## Tests

- `go test ./sources/apollo ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/apollo/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
