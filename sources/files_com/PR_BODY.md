## Summary

- Adds the `files_com` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Health endpoint: `/source-runtimes/health?source_id=files_com`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/files_com ./internal/sourceprojection -count=1`
- `make catalog-check`
