## Summary

- Replaces the generated Fivetran scaffold with provider-backed REST API families.
- Switches Fivetran auth to Basic API key and API secret credentials.
- Adds graph projection for users, groups, teams, roles, connections, destinations, logging configuration, networking agents, secrets managers, transformations, webhooks, and membership edges.
- Adds nested `data.items` list parsing in the shared JSON API runtime.
- Adds provider-shaped discover/read fixtures for every Fivetran runtime family and a full fixture replay test.

## Runtime contract

- Source type: `json_api`
- Auth model: `basic`
- Health endpoint: `/source-runtimes/health?source_id=fivetran`
- Provider health path: `/v1/account/info`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/internal/jsonapi ./sources/internal/fivetranapi ./sources/fivetran ./internal/sourceprojection ./internal/connectorcatalog ./tools/sourcefidelity -count=1`
- `make catalog-check`
- `make sourcegen-check`
- `make connector-catalog-fidelity-check`
- `go run ./tools/sourcefidelity -json-out /tmp/sourcefidelity.json -markdown-out /tmp/sourcefidelity.md`
