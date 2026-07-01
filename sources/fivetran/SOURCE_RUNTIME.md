# Fivetran

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Credential fields: `api_key` and `api_secret`, or `username` and `password`
- Default API base URL: `https://api.fivetran.com`
- Health path: `/v1/account/info`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fivetran`
- Provider API package: `sources/internal/fivetranapi`
- Health endpoint: `/source-runtimes/health?source_id=fivetran`
- Source health receipt: `sources/fivetran/source_health_receipt.json`
- EvidenceCAS reference kind: `fivetran.evidence_cas_reference`
- Pagination: `data.items` with `data.next_cursor`
- Request header: `Accept: application/json;version=2`
- Fixture coverage: 31 discover fixtures and 31 provider-shaped read fixtures

## Families

- `users`, emits `fivetran.users`, reads `/v1/users`
- `groups`, emits `fivetran.groups`, reads `/v1/groups`
- `group_users`, emits `fivetran.group_users`, reads `/v1/groups/{groupId}/users`
- `group_connections`, emits `fivetran.group_connections`, reads `/v1/groups/{groupId}/connections`
- `teams`, emits `fivetran.teams`, reads `/v1/teams`
- `team_users`, emits `fivetran.team_users`, reads `/v1/teams/{teamId}/users`
- `team_groups`, emits `fivetran.team_groups`, reads `/v1/teams/{teamId}/groups`
- `team_connections`, emits `fivetran.team_connections`, reads `/v1/teams/{teamId}/connections`
- `roles`, emits `fivetran.roles`, reads `/v1/roles`
- `user_group_memberships`, emits `fivetran.user_group_memberships`, reads `/v1/users/{userId}/groups`
- `user_connection_memberships`, emits `fivetran.user_connection_memberships`, reads `/v1/users/{userId}/connections`
- `destinations`, emits `fivetran.destinations`, reads `/v1/destinations`
- `destination_certificates`, emits `fivetran.destination_certificates`, reads `/v1/destinations/{destinationId}/certificates`
- `destination_fingerprints`, emits `fivetran.destination_fingerprints`, reads `/v1/destinations/{destinationId}/fingerprints`
- `connections`, emits `fivetran.connections`, reads `/v1/connections`
- `connection_certificates`, emits `fivetran.connection_certificates`, reads `/v1/connections/{connectionId}/certificates`
- `connection_fingerprints`, emits `fivetran.connection_fingerprints`, reads `/v1/connections/{connectionId}/fingerprints`
- `log_services`, emits `fivetran.log_services`, reads `/v1/external-logging`
- `webhooks`, emits `fivetran.webhooks`, reads `/v1/webhooks`
- `private_links`, emits `fivetran.private_links`, reads `/v1/private-links`
- `proxy_agents`, emits `fivetran.proxy_agents`, reads `/v1/proxy`
- `proxy_agent_connections`, emits `fivetran.proxy_agent_connections`, reads `/v1/proxy/{agentId}/connections`
- `hybrid_deployment_agents`, emits `fivetran.hybrid_deployment_agents`, reads `/v1/hybrid-deployment-agents`
- `connector_metadata`, emits `fivetran.connector_metadata`, reads `/v1/metadata/connector-types`
- `connector_sdk_packages`, emits `fivetran.connector_sdk_packages`, reads `/v1/connector-sdk/packages`
- `system_keys`, emits `fivetran.system_keys`, reads `/v1/system-keys`
- `external_secrets_managers`, emits `fivetran.external_secrets_managers`, reads `/v1/external-secrets-managers`
- `external_secrets_manager_entities`, emits `fivetran.external_secrets_manager_entities`, reads `/v1/external-secrets-managers-entities`
- `transformations`, emits `fivetran.transformations`, reads `/v1/transformations`
- `transformation_projects`, emits `fivetran.transformation_projects`, reads `/v1/transformation-projects`
- `transformation_package_metadata`, emits `fivetran.transformation_package_metadata`, reads `/v1/transformations/package-metadata`

## Scoped configuration

- `group_ids` or `group_id`: enables `group_users` and `group_connections`
- `team_ids` or `team_id`: enables `team_users`, `team_groups`, and `team_connections`
- `user_ids` or `user_id`: enables `user_group_memberships` and `user_connection_memberships`
- `connection_ids` or `connection_id`: enables `connection_certificates` and `connection_fingerprints`
- `destination_ids` or `destination_id`: enables `destination_certificates` and `destination_fingerprints`
- `proxy_agent_ids` or `proxy_agent_id`: enables `proxy_agent_connections`

## Provider gaps

- Fivetran does not expose a REST list endpoint for audit events. Runtime support covers log service configuration; event logs are delivered through Fivetran logging products.
- The old generated `accounts`, `records`, `policies`, and `audit_events` families were removed because they did not map to provider REST list endpoints.

## Tests

- `go test ./sources/internal/jsonapi ./sources/internal/fivetranapi ./sources/fivetran ./internal/sourceprojection ./internal/connectorcatalog ./tools/sourcefidelity -count=1`
- `make catalog-check`
- `make sourcegen-check`
- `make connector-catalog-fidelity-check`
- Source fidelity: reference, 100/100, 31 runtime families, 31 provider-shaped read fixtures, 31 deploy runtimes
