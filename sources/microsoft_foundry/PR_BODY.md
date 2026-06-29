## Summary

- Adds the `microsoft_foundry` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Health endpoint: `/source-runtimes/health?source_id=microsoft_foundry`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/microsoft_foundry ./internal/sourceprojection -count=1`
- `make catalog-check`
