# Aha

Provider-verified Source Runtime SDK for `aha`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: `Authorization: Bearer <API key or OAuth2 token>`
- Base URL: `${config.base_url}/api/v1` where `base_url` is the account-specific Aha! domain such as `https://company.aha.io`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/aha`
- Health endpoint: `/source-runtimes/health?source_id=aha`
- Source health receipt: `sources/aha/source_health_receipt.json`
- EvidenceCAS reference kind: `aha.evidence_cas_reference`

## Families

- `users`, emits `aha.users`, reads `GET /users`
- `products`, emits `aha.products`, reads `GET /products`
- `features`, emits `aha.features`, reads `GET /features`
- `releases`, emits `aha.releases`, reads `GET /products/{product_id}/releases`
- `audit_events`, emits `aha.audit_events`, reads `GET /audits`

## Tests

- `go test ./sources/aha ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/aha/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
