# Fivetran

Source Runtime SDK support for Fivetran account access, pipeline inventory, connection trust controls, logging configuration, system keys, and transformations.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Base URL: `https://api.fivetran.com`
- Health path: `/v1/account/info`
- List pagination: `data.items` records with `data.next_cursor`
- Scoped fanout: `user_ids`, `team_ids`, `group_ids`, `connection_ids`, `destination_ids`, `external_secret_manager_ids`, `proxy_agent_ids`, `connector_services`, `package_definition_ids`, plus table-column `connection_id`, `schema_name`, and `table_name`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fivetran`
- Health endpoint: `/source-runtimes/health?source_id=fivetran`
- Source health receipt: `sources/fivetran/source_health_receipt.json`
- Sensitive payload redaction: system keys `key` and `secret`; group service accounts `service_account`; webhooks `signing_key`

## Families

- `account_info`, emits `fivetran.account_info`, reads `/v1/account/info`
- `users`, emits `fivetran.users`, reads `/v1/users`
- `user_connections`, emits `fivetran.user_connections`, reads `/v1/users/{user_id}/connections`, scopes on `user_id`
- `user_groups`, emits `fivetran.user_groups`, reads `/v1/users/{user_id}/groups`, scopes on `user_id`
- `roles`, emits `fivetran.roles`, reads `/v1/roles`
- `teams`, emits `fivetran.teams`, reads `/v1/teams`
- `team_users`, emits `fivetran.team_users`, reads `/v1/teams/{team_id}/users`, scopes on `team_id`
- `team_connections`, emits `fivetran.team_connections`, reads `/v1/teams/{team_id}/connections`, scopes on `team_id`
- `team_groups`, emits `fivetran.team_groups`, reads `/v1/teams/{team_id}/groups`, scopes on `team_id`
- `groups`, emits `fivetran.groups`, reads `/v1/groups`
- `group_users`, emits `fivetran.group_users`, reads `/v1/groups/{group_id}/users`, scopes on `group_id`
- `group_connections`, emits `fivetran.group_connections`, reads `/v1/groups/{group_id}/connections`, scopes on `group_id`
- `group_public_keys`, emits `fivetran.group_public_keys`, reads `/v1/groups/{group_id}/public-key`, scopes on `group_id`
- `group_service_accounts`, emits `fivetran.group_service_accounts`, reads `/v1/groups/{group_id}/service-account`, scopes on `group_id`
- `destinations`, emits `fivetran.destinations`, reads `/v1/destinations`
- `connections`, emits `fivetran.connections`, reads `/v1/connections`
- `connection_certificates`, emits `fivetran.connection_certificates`, reads `/v1/connections/{connection_id}/certificates`, scopes on `connection_id`
- `connection_fingerprints`, emits `fivetran.connection_fingerprints`, reads `/v1/connections/{connection_id}/fingerprints`, scopes on `connection_id`
- `connection_schemas`, emits `fivetran.connection_schemas`, reads `/v1/connections/{connection_id}/schemas`, scopes on `connection_id`
- `connection_state`, emits `fivetran.connection_state`, reads `/v1/connections/{connection_id}/state`, scopes on `connection_id`
- `connection_table_columns`, emits `fivetran.connection_table_columns`, reads `/v1/connections/{connection_id}/schemas/{schema_name}/tables/{table_name}/columns`, scopes on `connection_id`, `schema_name`, and `table_name`
- `connector_sdk_packages`, emits `fivetran.connector_sdk_packages`, reads `/v1/connector-sdk/packages`
- `destination_certificates`, emits `fivetran.destination_certificates`, reads `/v1/destinations/{destination_id}/certificates`, scopes on `destination_id`
- `destination_fingerprints`, emits `fivetran.destination_fingerprints`, reads `/v1/destinations/{destination_id}/fingerprints`, scopes on `destination_id`
- `account_log_service`, emits `fivetran.account_log_service`, reads `/v1/external-logging/account`
- `log_services`, emits `fivetran.log_services`, reads `/v1/external-logging`
- `webhooks`, emits `fivetran.webhooks`, reads `/v1/webhooks`
- `external_secret_managers`, emits `fivetran.external_secret_managers`, reads `/v1/external-secrets-managers`
- `external_secret_manager_entities`, emits `fivetran.external_secret_manager_entities`, reads `/v1/external-secrets-managers-entities`
- `external_secret_manager_assignments`, emits `fivetran.external_secret_manager_assignments`, reads `/v1/external-secrets-managers/{external_secret_manager_id}/entities`, scopes on `external_secret_manager_id`
- `private_links`, emits `fivetran.private_links`, reads `/v1/private-links`
- `proxy_agents`, emits `fivetran.proxy_agents`, reads `/v1/proxy`
- `proxy_agent_connections`, emits `fivetran.proxy_agent_connections`, reads `/v1/proxy/{proxy_agent_id}/connections`, scopes on `proxy_agent_id`
- `hybrid_deployment_agents`, emits `fivetran.hybrid_deployment_agents`, reads `/v1/hybrid-deployment-agents`
- `public_connector_types`, emits `fivetran.public_connector_types`, reads `/public/connector-types`
- `connector_metadata`, emits `fivetran.connector_metadata`, reads `/v1/metadata/connector-types`
- `connector_metadata_details`, emits `fivetran.connector_metadata_details`, reads `/v1/metadata/connector-types/{service}`, scopes on `service`
- `system_keys`, emits `fivetran.system_keys`, reads `/v1/system-keys`
- `transformations`, emits `fivetran.transformations`, reads `/v1/transformations`
- `transformation_projects`, emits `fivetran.transformation_projects`, reads `/v1/transformation-projects`
- `transformation_package_metadata`, emits `fivetran.transformation_package_metadata`, reads `/v1/transformations/package-metadata`
- `transformation_package_details`, emits `fivetran.transformation_package_details`, reads `/v1/transformations/package-metadata/{package_definition_id}`, scopes on `package_definition_id`

## Tests

- `go test ./sources/internal/jsonapi ./sources/internal/fivetranapi ./sources/fivetran ./internal/sourceprojection -count=1`
- `make catalog-check`
- `make sourcegen-check`
