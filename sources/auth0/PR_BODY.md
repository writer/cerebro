## Summary

- Expands the `auth0` Source CDK runtime from users, roles, and logs to 13 Management API families.
- Adds graph projection for organizations, organization members, applications, connections, resource servers, API scopes, grants, user roles, authentication methods, Guardian factors, users, roles, and audit events.
- Adds deploy runtimes, fixtures, catalog contracts, and source-health metadata for the expanded runtime.
- Updates catalog maintenance so runtime-backed bespoke sources can pass the sourcegen gate when runtime-depth evidence is present.

## Runtime contract

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Health endpoint: `/source-runtimes/health?source_id=auth0`
- Freshness: `1h0m0s` for tenant logs, `24h0m0s` for configuration snapshots
- Fanout config: `organization_ids` for organization members; `user_ids` for user roles and authentication methods

## Tests

- `go test ./sources/auth0 ./sources/internal/auth0api ./internal/sourceprojection ./internal/connectorcatalog ./internal/connectordefinitions ./sources/internal/catalogruntime ./tools/catalogcheck ./tools/sourcedeploy ./tools/archtests -count=1`
- `make connector-catalog-maintenance connector-contract-check detection-catalog-check policy-mapping-check check-structural check-structural-test check-arch droid-review-sast`
