## Summary

- Promotes the `akeyless` Source Runtime SDK to provider-verified API proof.
- Maps Akeyless items, auth methods, roles, and analytics to documented Akeyless API endpoints.
- Uses the provider's documented JSON request-body token mechanism for runtime requests.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `akeyless_token_json_body`
- Health endpoint: `/source-runtimes/health?source_id=akeyless`
- Provider API proof score: 100
- Runtime depth: `reference_runtime`

## Tests

- `go test ./sources/akeyless ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/akeyless/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
