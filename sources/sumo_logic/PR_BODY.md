## Summary

- Adds the `sumo_logic` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `basic`
- Health endpoint: `/source-runtimes/health?source_id=sumo_logic`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/sumo_logic ./internal/sourceprojection -count=1`
- `make catalog-check`
