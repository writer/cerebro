## Summary

- Replaces the generated Fivetran scaffold with provider-backed Source CDK runtime families.
- Adds Basic API key authentication, Fivetran cursor pagination, scoped membership fanout, connection trust reads, logging and webhook reads, connector metadata, system keys, transformations, and system key payload redaction.
- Wires Fivetran event kinds into graph projection and the connector catalog.

## Runtime contract

- Source type: `json_api`
- Auth model: `basic`
- Health path: `/v1/account/info`
- Families: users, roles, teams, groups, memberships, destinations, connections, connection trust records, logging services, webhooks, private links, proxy agents, hybrid deployment agents, connector metadata, system keys, transformations
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/internal/jsonapi ./sources/internal/fivetranapi ./sources/fivetran ./internal/sourceprojection -count=1`
- `make catalog-check`
- `make sourcegen-check`
