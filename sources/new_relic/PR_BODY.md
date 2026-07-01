## Summary

- Replaces the New Relic generated REST-shaped runtime with a NerdGraph runtime.
- Reads monitored entities through entity search, AI issues through account-scoped issue APIs, and audit rows through NrAuditEvent NRQL.
- Updates catalog provider API metadata, coverage contracts, deploy config, fixtures, and runtime docs.

## Runtime Contract

- Source type: `graphql`
- Auth model: `api_key`
- Endpoint: `/graphql`
- Required config: `api_key`; `account_id` for findings and audit events

## Tests

- `go test ./sources/new_relic ./internal/sourceprojection -count=1`
- `go run ./tools/catalogcheck`
