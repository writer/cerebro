## Summary

- Expands the Auth0 runtime from users, roles, and logs into applications, connections, organizations, organization members, role users, and organization member roles.
- Adds Auth0 Management API pagination for include_totals page wrappers and checkpoint-style fanout, including organization/user scoped role traversal.
- Projects Auth0 applications, connections, organizations, memberships, role assignments, and role entitlements onto the graph.

## Runtime contract

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Health endpoint: `/source-runtimes/health?source_id=auth0`
- Freshness: `24h0m0s`
- Required scopes: `read:clients`, `read:connections`, `read:logs`, `read:organizations`, `read:organization_members`, `read:organization_member_roles`, `read:roles`, `read:users`

## Tests

- `go test ./sources/auth0 ./sources/internal/jsonapi ./internal/sourceprojection -count=1`
- `make catalog-check`
- `make sourcegen-test`
- `make sourcegen-check`
