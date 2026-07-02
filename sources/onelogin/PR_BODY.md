## Summary
- Adds OneLogin Source CDK runtime depth for users, groups, roles, apps, privileges, mappings, app rules, MFA devices, scoped assignments, and audit events.
- Projects OneLogin runtime events into identity users, groups, applications, credentials, policy rules, app assignments, role assignments, group memberships, and audit activity.
- Documents scoped fanout requirements and catalog coverage for the promoted runtime.

## Tests
- `go test ./sources/internal/jsonapi ./sources/onelogin ./internal/sourceprojection -count=1`
- `make catalog-check`
- `make connector-catalog-fidelity-check`
