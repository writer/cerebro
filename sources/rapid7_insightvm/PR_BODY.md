## Summary

- Adds the `rapid7_insightvm` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Health endpoint: `/source-runtimes/health?source_id=rapid7_insightvm`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/rapid7_insightvm ./internal/sourceprojection -count=1`
- `make catalog-check`
