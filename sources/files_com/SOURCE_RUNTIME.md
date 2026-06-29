# Files.com

Generated Source Runtime SDK scaffold for `files_com`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/files_com`
- Health endpoint: `/source-runtimes/health?source_id=files_com`
- Source health receipt: `sources/files_com/source_health_receipt.json`
- EvidenceCAS reference kind: `files_com.evidence_cas_reference`

## Families

- `external_event`, emits `files_com.external_event`, reads `/external_events`
- `api_key`, emits `files_com.api_key`, reads `/api_keys`
- `group`, emits `files_com.group`, reads `/groups`
- `group_user`, emits `files_com.group_user`, reads `/group_users`
- `action_notification_export_result`, emits `files_com.action_notification_export_result`, reads `/action_notification_export_results`
- `permission`, emits `files_com.permission`, reads `/permissions`
- `login`, emits `files_com.login`, reads `/history/login`
- `site_api_key`, emits `files_com.site_api_key`, reads `/site/api_keys`
- `user_api_key`, emits `files_com.user_api_key`, reads `/user/api_keys`
- `exavault_reserved`, emits `files_com.exavault_reserved`, reads `/ip_addresses/exavault-reserved`
- `user_group`, emits `files_com.user_group`, reads `/user/groups`
- `user`, emits `files_com.user`, reads `/users`

## Tests

- `go test ./sources/files_com ./internal/sourceprojection -count=1`
- `make catalog-check`
