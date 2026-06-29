## Summary

- Adds the `api2cart` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Health endpoint: `/source-runtimes/health?source_id=api2cart`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/api2cart ./internal/sourceprojection -count=1`
- `make catalog-check`
