## Summary

- Promotes the `airbrake` Source Runtime SDK to provider-verified API proof.
- Reshapes generated placeholder families to documented Airbrake API resources: projects, groups, deploys, source maps, and project activities.
- Syncs runtime paths, connector catalog metadata, fixtures, projections, and source-health metadata.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `key` query parameter
- Health endpoint: `/source-runtimes/health?source_id=airbrake`
- Provider API proof: 100, verified

## Tests

- `go test ./sources/airbrake ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/airbrake/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
