## Summary

- Adds the `crowdstrike_falcon` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Health endpoint: `/source-runtimes/health?source_id=crowdstrike_falcon`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/crowdstrike_falcon ./internal/sourceprojection -count=1`
- `make catalog-check`
