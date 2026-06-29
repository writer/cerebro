## Summary

- Adds the `prisma_cloud` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `jwt`
- Health endpoint: `/source-runtimes/health?source_id=prisma_cloud`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/prisma_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
