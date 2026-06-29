## Summary

- Adds the `azure_devops` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Health endpoint: `/source-runtimes/health?source_id=azure_devops`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/azure_devops ./internal/sourceprojection -count=1`
- `make catalog-check`
