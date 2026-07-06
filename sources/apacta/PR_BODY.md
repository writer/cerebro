## Summary

- Promotes the `apacta` Source Runtime SDK to provider-verified API proof using the Apacta Partner API OpenAPI document.
- Reshapes the generated family set to documented Partner API resources: activities, cities, contact people, project users, and users.
- Removes generated families that do not have stable documented Partner API endpoints.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: `Authorization: Bearer <token>`
- Health endpoint: `/source-runtimes/health?source_id=apacta`
- Provider API proof score: `100`
- Runtime depth level: `reference_runtime`

## Tests

- `go test ./sources/apacta ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/apacta/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
