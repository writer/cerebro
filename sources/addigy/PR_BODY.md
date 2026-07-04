## Summary

- Promotes the `addigy` source to the Addigy API v2 contract.
- Replaces removed API v1 scaffold paths with v2 device, user, group, policy, and system-event endpoints.
- Adds shared JSON API support for POST request-body pagination.
- Updates graph projections, fixtures, catalog proof, deploy metadata, and tests.

## Runtime contract

- Source type: `addigy_api_v2`
- Auth model: `api_key`
- Health endpoint: `/source-runtimes/health?source_id=addigy`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/internal/jsonapi ./sources/addigy ./internal/sourceprojection -count=1`
- `make lint-sources catalog-check sourcegen-check`
- `make check-structural check-structural-test check-arch`
- `make connector-catalog-review connector-api-discovery`
