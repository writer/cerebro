## Summary

- Promotes the `alteryx` Source Runtime SDK to provider-verified API proof.
- Maps the runtime to documented Alteryx Server API endpoints for users, user groups, workflows, collections, and audit events.
- Updates the runtime adapter, catalog proof, connector definition, health receipt, fixtures, deploy manifest, and projection registrations.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: OAuth2 bearer access token in the Authorization header
- Health endpoint: `/source-runtimes/health?source_id=alteryx`
- Provider API proof score: 100

## Tests

- `go test ./sources/alteryx ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/alteryx/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
