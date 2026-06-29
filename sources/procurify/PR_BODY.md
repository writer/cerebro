## Summary

- Adds the `procurify` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=procurify`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/procurify ./internal/sourceprojection -count=1`
- `make catalog-check`
