## Summary

- Promotes the `alchemer` Source Runtime SDK to provider-verified API proof.
- Reshapes generated families to documented Alchemer REST API v5 resources for accounts, users, teams, surveys, contact lists, and SSO integrations.
- Updates runtime paths, auth mechanics, connector metadata, fixtures, health receipt, and projection wiring.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `api_token` and `api_token_secret` query parameters
- Health endpoint: `/source-runtimes/health?source_id=alchemer`
- Runtime depth: reference runtime
- Provider API proof: verified

## Tests

- `go test ./sources/alchemer ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/alchemer/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
