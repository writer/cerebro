## Summary

- Adds the `planview_adaptivework` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=planview_adaptivework`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/planview_adaptivework ./internal/sourceprojection -count=1`
- `make catalog-check`
