## Summary

- Promotes the `aircall` Source Runtime SDK to provider-verified API proof.
- Reshapes generated placeholder families to documented Aircall Public API resources: users, teams, calls, contacts, and numbers.
- Updates the runtime adapter, connector definition, health receipt, fixtures, and projection registration to use real Aircall endpoints.

## Runtime contract

- Source type: `json_api`
- Auth model: `basic`
- Auth mechanics: HTTP Basic API ID/API token header
- Base URL: `https://api.aircall.io/v1`
- Health endpoint: `/source-runtimes/health?source_id=aircall`
- Provider API proof score: 100 (`verified`)

## Tests

- `go test ./sources/aircall ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/aircall/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
