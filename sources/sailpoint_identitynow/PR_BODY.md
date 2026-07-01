## Summary

- Replaces the generated SailPoint placeholder runtime with a v2025 Identity Security Cloud runtime.
- Adds OAuth client-credentials auth, offset pagination, scoped fanout reads, deploy coverage, provider-shaped fixtures, and graph projectors for 28 families.
- Updates the connector catalog entry to use tenant-scoped v2025 API paths and concrete projection templates.

## Runtime Contract

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Base URL: `https://${config.tenant}.api.identitynow.com/v2025`
- Health path: `/identities`
- Runtime families: identities, accounts, account entitlements, sources, source schemas, source health, source provisioning policies, source schedules, access profiles, access profile entitlements, roles, role assigned identities, role entitlements, role dimensions, entitlements, identity entitlements, identity role assignments, identity profiles, lifecycle states, workgroups, workgroup members, campaigns, certifications, certification access review items, access request status, account activities, personal access tokens, segments.

## Tests

- `go test ./sources/internal/sailpointapi ./sources/sailpoint_identitynow ./internal/sourceprojection ./internal/connectorcatalog -count=1`
- `go run ./tools/connectorcatalogreview -root . -json-out /tmp/connectorcatalog-review.json -markdown-out /tmp/connectorcatalog-review.md -max-items 10`
- `make catalog-check`
