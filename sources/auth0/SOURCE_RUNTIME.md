# Auth0

Auth0 source runtime for Management API identity, application, organization, role assignment, and audit data.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/auth0`
- Health endpoint: `/source-runtimes/health?source_id=auth0`
- Source health receipt: `sources/auth0/source_health_receipt.json`
- EvidenceCAS reference kind: `auth0.evidence_cas_reference`

## Families

- `users`, emits `auth0.users`, reads `/users`
- `roles`, emits `auth0.roles`, reads `/roles`
- `audit_events`, emits `auth0.audit_events`, reads `/logs`
- `clients`, emits `auth0.clients`, reads `/clients`
- `connections`, emits `auth0.connections`, reads `/connections`
- `organizations`, emits `auth0.organizations`, reads `/organizations`
- `organization_members`, emits `auth0.organization_members`, reads `/organizations/{organization_id}/members` across configured `organization_ids`
- `role_users`, emits `auth0.role_users`, reads `/roles/{role_id}/users` across configured `role_ids`
- `organization_member_roles`, emits `auth0.organization_member_roles`, reads `/organizations/{organization_id}/members/{user_id}/roles` across configured `organization_ids` and `user_ids`

Direct inventory families use durable watermark checkpoints for incremental source-runtime sync. Role-user and organization membership fanout families preserve provider pagination cursors within each configured scope.

## Tests

- `go test ./sources/auth0 ./internal/sourceprojection -count=1`
- `make catalog-check`
