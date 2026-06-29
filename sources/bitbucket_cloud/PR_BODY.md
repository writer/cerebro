## Summary

- Adds the `bitbucket_cloud` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Health endpoint: `/source-runtimes/health?source_id=bitbucket_cloud`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/bitbucket_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
