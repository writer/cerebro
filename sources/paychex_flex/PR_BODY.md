## Summary

- Adds the `paychex_flex` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=paychex_flex`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/paychex_flex ./internal/sourceprojection -count=1`
- `make catalog-check`
