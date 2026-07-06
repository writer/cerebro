## Summary

- Promotes the `activtrak` Source Runtime SDK adapter to provider-verified API proof.
- Maps runtime families to documented ActivTrak SCIM, Administration, and Reports API endpoints.
- Updates the source runtime metadata, connector definition, fixtures, and projection registrations to match the real API resources.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key` via `x-api-key` header
- Health endpoint: `/source-runtimes/health?source_id=activtrak`
- Provider API proof score: 100

## Tests

- `go test ./sources/activtrak ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/activtrak/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
