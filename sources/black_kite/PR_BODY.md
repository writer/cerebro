## Summary

- Adds the `black_kite` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=black_kite`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/black_kite ./internal/sourceprojection -count=1`
- `make catalog-check`
