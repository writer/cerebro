## Summary

- Promotes the `apollo` Source Runtime SDK to provider-verified API proof.
- Maps the runtime to Apollo's documented workspace users, saved accounts, and saved contacts endpoints.
- Updates runtime paths, built-in connector metadata, health receipt, fixtures, graph projection registration, and tests.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Health endpoint: `/source-runtimes/health?source_id=apollo`
- Provider API proof: `verified` / 100
- Runtime depth: `reference_runtime`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/apollo ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/apollo/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
