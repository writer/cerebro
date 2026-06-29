## Summary

- Adds the `signl4` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Health endpoint: `/source-runtimes/health?source_id=signl4`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/signl4 ./internal/sourceprojection -count=1`
- `make catalog-check`
