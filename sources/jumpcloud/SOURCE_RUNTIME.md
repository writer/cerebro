# JumpCloud

Source Runtime adapter for JumpCloud directory, device, application, group membership, and Directory Insights event data.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `x-api-key` header with optional `x-org-id`
- Base URL: `https://console.jumpcloud.com/api`
- Directory Insights URL: `https://api.jumpcloud.com/insights/directory/v1`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/jumpcloud`
- Health endpoint: `/source-runtimes/health?source_id=jumpcloud`
- Source health receipt: `sources/jumpcloud/source_health_receipt.json`
- Emits identity users, identity groups, managed systems, SSO applications, user-group membership edges, system groups, and audit events.

## Families

- `users`, emits `jumpcloud.users`, reads `GET /systemusers`
- `groups`, emits `jumpcloud.groups`, reads `GET /v2/usergroups`
- `systems`, emits `jumpcloud.systems`, reads `GET /systems`
- `applications`, emits `jumpcloud.applications`, reads `GET /applications`
- `system_groups`, emits `jumpcloud.system_groups`, reads `GET /v2/systemgroups`
- `group_members`, emits `jumpcloud.group_members`, reads `GET /v2/usergroups/{group_id}/members`
- `audit_events`, emits `jumpcloud.audit_events`, reads `POST https://api.jumpcloud.com/insights/directory/v1/events`

## Tests

- `go test ./sources/jumpcloud ./internal/sourceprojection -count=1`
- `make lint-sources catalog-check sourcegen-check check-structural check-structural-test check-arch`
- `make connector-catalog-review connector-api-discovery`
