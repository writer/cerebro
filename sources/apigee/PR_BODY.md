## Summary

- Promotes the `apigee` Source Runtime SDK to provider-verified API proof.
- Reshapes generated placeholder families to documented Google Cloud Apigee API resources: organizations, API proxies, deployments, developers, and apps.
- Aligns runtime paths, fixtures, connector definition, deploy config, and source health metadata with the Apigee REST discovery document.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token` carrying a Google OAuth2 access token
- Provider API proof score: `100`
- Provider API proof level: `verified`
- Runtime depth level: `reference_runtime`

## Tests

- `go test ./sources/apigee ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/apigee/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
