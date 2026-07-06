# Aircall

Provider-verified Source Runtime SDK for `aircall`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Auth mechanics: HTTP Basic authentication with Aircall API ID as username and API token as password
- Default base URL: `https://api.aircall.io/v1`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/aircall`
- Health endpoint: `/source-runtimes/health?source_id=aircall`
- Adapter health path: `GET /ping`
- Source health receipt: `sources/aircall/source_health_receipt.json`
- EvidenceCAS reference kind: `aircall.evidence_cas_reference`

## Families

- `users`, emits `aircall.users`, reads `GET /users` from the documented Aircall Public API user list.
- `teams`, emits `aircall.teams`, reads `GET /teams` from the documented Aircall Public API team list.
- `calls`, emits `aircall.calls`, reads `GET /calls` from the documented Aircall Public API call list as call activity evidence.
- `contacts`, emits `aircall.contacts`, reads `GET /contacts` from the documented Aircall Public API contact list.
- `numbers`, emits `aircall.numbers`, reads `GET /numbers` from the documented Aircall Public API number list.

## Tests

- `go test ./sources/aircall ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/aircall/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
