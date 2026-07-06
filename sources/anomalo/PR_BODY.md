## Summary

- Promotes the `anomalo` source to provider-verified API proof.
- Reshapes the generated placeholder families to Anomalo's documented public API resources: warehouses, tables, checks, notification channels, and organizations.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=anomalo`
- Freshness: `24h0m0s`

## Provider API proof outcome

- Outcome: promoted, `provider_api.status=verified`
- Provider API proof score: 100
- Runtime depth level: `reference_runtime`
- Evidence reviewed: Anomalo's PyPI client package, public Go client documentation, and Terraform provider resource documentation.

## Tests

- `go test ./sources/anomalo ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/anomalo/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
- `go test ./internal/sourcecdk ./tools/catalogcheck ./tools/archtests -count=1`
- `make check-structural check-structural-test check-arch`
