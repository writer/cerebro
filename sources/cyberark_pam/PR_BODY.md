## Summary

- Adds the `cyberark_pam` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Health endpoint: `/source-runtimes/health?source_id=cyberark_pam`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/cyberark_pam ./internal/sourceprojection -count=1`
- `make catalog-check`
