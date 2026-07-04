## Summary

- Promotes the provider-backed portion of the `beezup` Source Runtime contract.
- Updates API-key authentication to use the documented `Ocp-Apim-Subscription-Key` header.
- Rewrites `filteroperator` to the documented exclusion filter operator endpoint.
- Removes generated `filter` and `rule` runtime paths from the active surface because provider operation rows are not available.

## Provider API result

- Status: partial provider mapping with explicit invalidation.
- Verified families: `alert`, `autoimport`, `beezupcolumn`, `catalogcolumn`, `category`, `channelcatalog`, `customcolumn`, `filteroperator`, `offer`, `random`.
- Invalidated families: `filter`, `rule`.
- Missing paths:
  - `/v2/user/analytics/{storeId}/reports/filters`
  - `/v2/user/analytics/{storeId}/rules`

## Runtime fixes

- Auth header now matches the provider client: `Ocp-Apim-Subscription-Key`.
- `filteroperator` now reads `/v2/user/channelCatalogs/exclusionFilterOperators`.

## Tests

- `go test ./sources/beezup ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `make catalog-check`
- `make connector-catalog-review connector-api-discovery`
