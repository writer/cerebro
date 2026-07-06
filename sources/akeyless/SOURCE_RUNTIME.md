# Akeyless

Source Runtime SDK adapter for `akeyless` using the provider-documented Akeyless API.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: Akeyless API token sent as the `token` field in each JSON request body
- Base URL: `https://api.akeyless.io`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/akeyless`
- Health endpoint: `/source-runtimes/health?source_id=akeyless`
- Source health receipt: `sources/akeyless/source_health_receipt.json`
- EvidenceCAS reference kind: `akeyless.evidence_cas_reference`

## Families

- `items`, emits `akeyless.items`, reads `POST /list-items`
- `auth_methods`, emits `akeyless.auth_methods`, reads `POST /list-auth-methods`
- `roles`, emits `akeyless.roles`, reads `POST /list-roles`
- `analytics`, emits `akeyless.analytics`, reads `POST /get-analytics-data`

## Tests

- `go test ./sources/akeyless ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/akeyless/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
