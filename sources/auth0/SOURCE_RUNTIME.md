# Auth0

Auth0 Management API Source CDK adapter.

## Runtime Input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Token audience: `https://${config.domain}/api/v2/`
- Freshness expectation: `24h0m0s` for configuration snapshots, `1h0m0s` for tenant logs
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime Output

- Adapter package: `sources/auth0`
- Family definitions: `sources/internal/auth0api`
- Health endpoint: `/source-runtimes/health?source_id=auth0`
- Source health receipt: `sources/auth0/source_health_receipt.json`
- EvidenceCAS reference kind: `auth0.evidence_cas_reference`

## Families

- `users`, emits `auth0.users`, reads `GET /users`
- `roles`, emits `auth0.roles`, reads `GET /roles`
- `audit_events`, emits `auth0.audit_events`, reads `GET /logs`
- `organizations`, emits `auth0.organizations`, reads `GET /organizations`
- `organization_members`, emits `auth0.organization_members`, reads `GET /organizations/{organization_id}/members`
- `clients`, emits `auth0.clients`, reads `GET /clients`
- `connections`, emits `auth0.connections`, reads `GET /connections`
- `resource_servers`, emits `auth0.resource_servers`, reads `GET /resource-servers`
- `client_grants`, emits `auth0.client_grants`, reads `GET /client-grants`
- `grants`, emits `auth0.grants`, reads `GET /grants`
- `user_roles`, emits `auth0.user_roles`, reads `GET /users/{user_id}/roles`
- `user_authentication_methods`, emits `auth0.user_authentication_methods`, reads `GET /users/{user_id}/authentication-methods`
- `guardian_factors`, emits `auth0.guardian_factors`, reads `GET /guardian/factors`

`organization_members` requires `organization_id` or `organization_ids`. `user_roles` and `user_authentication_methods` require `user_id` or `user_ids`.

## Tests

- `go test ./sources/auth0 ./sources/internal/auth0api ./internal/sourceprojection -count=1`
- `make catalog-check`
