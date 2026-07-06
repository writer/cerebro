## Summary

- Promotes the `amplitude` Source Runtime SDK to provider-verified API proof.
- Maps the runtime to Amplitude's documented SCIM users and groups endpoints for identity and access inventory.
- Updates runtime paths, built-in connector metadata, health receipt, fixtures, graph projection registration, and tests.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=amplitude`
- Provider API proof: `verified` / 100
- Runtime depth: `reference_runtime`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/amplitude ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/amplitude/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
