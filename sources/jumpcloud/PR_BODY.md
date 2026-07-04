## Summary

- Promotes the `jumpcloud` Source Runtime contract to provider-verified API proof.
- Maps the runtime families to JumpCloud API v1, API v2, and Directory Insights endpoints.
- Refreshes the source runtime notes and health receipt to match the implemented runtime.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `x-api-key` header with optional `x-org-id`
- Health endpoint: `/source-runtimes/health?source_id=jumpcloud`
- Families: `users`, `groups`, `systems`, `applications`, `system_groups`, `group_members`, `audit_events`

## Tests

- `go test ./sources/jumpcloud ./internal/sourceprojection -count=1`
- `make lint-sources catalog-check sourcegen-check check-structural check-structural-test check-arch`
- `make connector-catalog-review connector-api-discovery`
- `make docs-drift-check oss-audit`
