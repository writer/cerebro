## Summary

- Promotes the `alation` Source Runtime SDK mapping to provider-verified API proof.
- Reshapes generated placeholder families to documented Alation resources: users, groups, data sources, policies, and terms.
- Updates runtime paths, catalog metadata, connector definition, fixtures, and projection wiring to match the documented API.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key` via Alation's `TOKEN` header
- Health endpoint: `/source-runtimes/health?source_id=alation`
- Runtime depth: reference runtime
- Provider API proof score: 100

## Tests

- `go test ./sources/alation ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/alation/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
