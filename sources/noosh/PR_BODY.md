## Summary

- Adds the `noosh` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `basic`
- Health endpoint: `/source-runtimes/health?source_id=noosh`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/noosh ./internal/sourceprojection -count=1`
- `make catalog-check`
