## Summary

- Adds the `veracode` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `signature`
- Health endpoint: `/source-runtimes/health?source_id=veracode`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/veracode ./internal/sourceprojection -count=1`
- `make catalog-check`
