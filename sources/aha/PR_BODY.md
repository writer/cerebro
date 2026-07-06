## Summary

- Promotes the `aha` Source Runtime SDK to provider-verified API proof.
- Maps users, products, features, product-scoped releases, and audits to documented Aha! REST API endpoints backed by the published OpenAPI document.
- Reshapes generated placeholder repository/deployment/project families to the provider's real product-development resources.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=aha`
- Provider API proof score: 100 (`verified`)
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/aha ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/aha/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
