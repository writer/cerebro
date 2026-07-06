## Summary

- Promotes the `airfocus` Source Runtime SDK to provider-verified API proof.
- Maps users, workspaces, workspace groups, item link types, and API key metadata to documented Airfocus REST API endpoints backed by the published OpenAPI document.
- Reshapes generated placeholder project, repository, deployment, and audit-event families to the provider's real product-management resources.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=airfocus`
- Provider API proof score: 100 (`verified`)
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/airfocus ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/airfocus/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
