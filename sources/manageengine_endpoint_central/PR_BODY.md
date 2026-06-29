## Summary

- Adds the `manageengine_endpoint_central` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=manageengine_endpoint_central`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/manageengine_endpoint_central ./internal/sourceprojection -count=1`
- `make catalog-check`
