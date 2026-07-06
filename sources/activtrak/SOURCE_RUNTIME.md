# ActivTrak

Provider-verified Source Runtime SDK adapter for `activtrak`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `x-api-key` header
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/activtrak`
- Health endpoint: `/source-runtimes/health?source_id=activtrak`
- Source health receipt: `sources/activtrak/source_health_receipt.json`
- EvidenceCAS reference kind: `activtrak.evidence_cas_reference`

## Families

- `users`, emits `activtrak.users`, reads `GET /scim/v1/users`
- `groups`, emits `activtrak.groups`, reads `GET /scim/v1/groups`
- `clients`, emits `activtrak.clients`, reads `GET /admin/v1/clients`
- `consumers`, emits `activtrak.consumers`, reads `GET /admin/v1/consumers`
- `activity_log`, emits `activtrak.activity_log`, reads `GET /reports/v2/activitylog`

## Tests

- `go test ./sources/activtrak ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/activtrak/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
