## Summary

- Promotes the `airbyte_cloud` Source Runtime SDK to provider-verified API proof.
- Maps runtime families to documented Airbyte API endpoints for users, organizations, sources, permissions, and connections.
- Updates the adapter, catalog metadata, connector definition, fixtures, projections, deploy manifest, and source-health receipt to match the documented API.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: `bearer_authorization_header`
- Health endpoint: `/source-runtimes/health?source_id=airbyte_cloud`
- Freshness: `24h0m0s`
- Provider API proof score: `100`
- Provider API proof level: `verified`

## Tests

- `go test ./sources/airbyte_cloud ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/airbyte_cloud/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
