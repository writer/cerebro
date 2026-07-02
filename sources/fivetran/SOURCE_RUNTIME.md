# Fivetran

Source Runtime SDK support for Fivetran account access, pipeline inventory, connection trust controls, logging configuration, system keys, and transformations.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Base URL: `https://api.fivetran.com`
- Health path: `/v1/account/info`
- List pagination: `data.items` records with `data.next_cursor`
- Scoped fanout: `user_ids`, `team_ids`, `group_ids`, and `connection_ids`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fivetran`
- Health endpoint: `/source-runtimes/health?source_id=fivetran`
- Source health receipt: `sources/fivetran/source_health_receipt.json`
- System key payload redaction: `key`, `secret`

## Families

- `users`, emits `fivetran.users`, reads `/v1/users`
- `user_connections`, emits `fivetran.user_connections`, reads `/v1/users/{user_id}/connections`
- `user_groups`, emits `fivetran.user_groups`, reads `/v1/users/{user_id}/groups`
- `roles`, emits `fivetran.roles`, reads `/v1/roles`
- `teams`, emits `fivetran.teams`, reads `/v1/teams`
- `team_users`, emits `fivetran.team_users`, reads `/v1/teams/{team_id}/users`
- `team_connections`, emits `fivetran.team_connections`, reads `/v1/teams/{team_id}/connections`
- `team_groups`, emits `fivetran.team_groups`, reads `/v1/teams/{team_id}/groups`
- `groups`, emits `fivetran.groups`, reads `/v1/groups`
- `group_users`, emits `fivetran.group_users`, reads `/v1/groups/{group_id}/users`
- `group_connections`, emits `fivetran.group_connections`, reads `/v1/groups/{group_id}/connections`
- `destinations`, emits `fivetran.destinations`, reads `/v1/destinations`
- `connections`, emits `fivetran.connections`, reads `/v1/connections`
- `connection_certificates`, emits `fivetran.connection_certificates`, reads `/v1/connections/{connection_id}/certificates`
- `connection_fingerprints`, emits `fivetran.connection_fingerprints`, reads `/v1/connections/{connection_id}/fingerprints`
- `log_services`, emits `fivetran.log_services`, reads `/v1/external-logging`
- `webhooks`, emits `fivetran.webhooks`, reads `/v1/webhooks`
- `private_links`, emits `fivetran.private_links`, reads `/v1/private-links`
- `proxy_agents`, emits `fivetran.proxy_agents`, reads `/v1/proxy`
- `hybrid_deployment_agents`, emits `fivetran.hybrid_deployment_agents`, reads `/v1/hybrid-deployment-agents`
- `connector_metadata`, emits `fivetran.connector_metadata`, reads `/v1/metadata/connector-types`
- `system_keys`, emits `fivetran.system_keys`, reads `/v1/system-keys`
- `transformations`, emits `fivetran.transformations`, reads `/v1/transformations`

## Tests

- `go test ./sources/internal/jsonapi ./sources/internal/fivetranapi ./sources/fivetran ./internal/sourceprojection -count=1`
- `make catalog-check`
- `make sourcegen-check`
