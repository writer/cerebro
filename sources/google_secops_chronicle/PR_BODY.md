## Summary

- Adds the `google_secops_chronicle` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `jwt`
- Health endpoint: `/source-runtimes/health?source_id=google_secops_chronicle`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/google_secops_chronicle ./internal/sourceprojection -count=1`
- `make catalog-check`
