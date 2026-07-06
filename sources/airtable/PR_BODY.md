## Summary

- Promotes the `airtable` Source Runtime SDK to provider-verified API proof.
- Maps bases, enterprise users, and audit log events to Airtable's documented Web API endpoints.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=airtable`
- Freshness: `24h0m0s`
- Runtime depth: `reference_runtime`
- Provider API proof: `verified` (100)

## Tests

- `go test ./sources/airtable ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/airtable/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
