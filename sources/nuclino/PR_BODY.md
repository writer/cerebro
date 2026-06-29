## Summary

- Adds the `nuclino` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=nuclino`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/nuclino ./internal/sourceprojection -count=1`
- `make catalog-check`
