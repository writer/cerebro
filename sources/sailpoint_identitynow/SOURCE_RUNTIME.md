# SailPoint Identity Security Cloud

Source Runtime SDK package for `sailpoint_identitynow`.

## Runtime Input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Token endpoint: `https://${config.tenant}.api.identitynow.com/oauth/token`
- API base URL: `https://${config.tenant}.api.identitynow.com/v2025`
- Health path: `/identities`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error`, `auth_error`, `rate_limit`, `schema_drift`

## Runtime Output

- Adapter package: `sources/sailpoint_identitynow`
- Provider API mapping: official SailPoint v2025 REST API
- Source health receipt: `sources/sailpoint_identitynow/source_health_receipt.json`
- Graph projection: 28 emitted kinds registered in `internal/sourceprojection`

## Families

- `identities`, emits `sailpoint_identitynow.identities`, reads `/identities`
- `accounts`, emits `sailpoint_identitynow.accounts`, reads `/accounts`
- `account_entitlements`, emits `sailpoint_identitynow.account_entitlements`, reads `/accounts/{id}/entitlements`, requires `account_ids`
- `sources`, emits `sailpoint_identitynow.sources`, reads `/sources`
- `source_schemas`, emits `sailpoint_identitynow.source_schemas`, reads `/sources/{sourceId}/schemas`, requires `source_ids`
- `source_health`, emits `sailpoint_identitynow.source_health`, reads `/sources/{sourceId}/source-health`, requires `source_ids`
- `source_provisioning_policies`, emits `sailpoint_identitynow.source_provisioning_policies`, reads `/sources/{sourceId}/provisioning-policies`, requires `source_ids`
- `source_schedules`, emits `sailpoint_identitynow.source_schedules`, reads `/sources/{sourceId}/schedules`, requires `source_ids`
- `access_profiles`, emits `sailpoint_identitynow.access_profiles`, reads `/access-profiles`
- `access_profile_entitlements`, emits `sailpoint_identitynow.access_profile_entitlements`, reads `/access-profiles/{id}/entitlements`, requires `access_profile_ids`
- `roles`, emits `sailpoint_identitynow.roles`, reads `/roles`
- `role_assigned_identities`, emits `sailpoint_identitynow.role_assigned_identities`, reads `/roles/{id}/assigned-identities`, requires `role_ids`
- `role_entitlements`, emits `sailpoint_identitynow.role_entitlements`, reads `/roles/{id}/entitlements`, requires `role_ids`
- `role_dimensions`, emits `sailpoint_identitynow.role_dimensions`, reads `/roles/{roleId}/dimensions`, requires `role_ids`
- `entitlements`, emits `sailpoint_identitynow.entitlements`, reads `/entitlements`
- `identity_entitlements`, emits `sailpoint_identitynow.identity_entitlements`, reads `/entitlements/identities/{id}/entitlements`, requires `identity_ids`
- `identity_role_assignments`, emits `sailpoint_identitynow.identity_role_assignments`, reads `/identities/{identityId}/role-assignments`, requires `identity_ids`
- `identity_profiles`, emits `sailpoint_identitynow.identity_profiles`, reads `/identity-profiles`
- `lifecycle_states`, emits `sailpoint_identitynow.lifecycle_states`, reads `/identity-profiles/{identity-profile-id}/lifecycle-states`, requires `identity_profile_ids`
- `workgroups`, emits `sailpoint_identitynow.workgroups`, reads `/workgroups`
- `workgroup_members`, emits `sailpoint_identitynow.workgroup_members`, reads `/workgroups/{workgroupId}/members`, requires `workgroup_ids`
- `campaigns`, emits `sailpoint_identitynow.campaigns`, reads `/campaigns`
- `certifications`, emits `sailpoint_identitynow.certifications`, reads `/certifications`
- `certification_access_review_items`, emits `sailpoint_identitynow.certification_access_review_items`, reads `/certifications/{id}/access-review-items`, requires `certification_ids`
- `access_request_status`, emits `sailpoint_identitynow.access_request_status`, reads `/access-request-status`
- `account_activities`, emits `sailpoint_identitynow.account_activities`, reads `/account-activities`
- `personal_access_tokens`, emits `sailpoint_identitynow.personal_access_tokens`, reads `/personal-access-tokens`
- `segments`, emits `sailpoint_identitynow.segments`, reads `/segments`

## Tests

- `go test ./sources/internal/sailpointapi ./sources/sailpoint_identitynow ./internal/sourceprojection ./internal/connectorcatalog -count=1`
- `go run ./tools/connectorcatalogreview -root . -json-out /tmp/connectorcatalog-review.json -markdown-out /tmp/connectorcatalog-review.md -max-items 10`
- `make catalog-check`
