# OneLogin

OneLogin Source CDK adapter for identity inventory, application access, delegated administration, MFA posture, policy rules, and audit events.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Base URL: `https://${config.subdomain}.onelogin.com`
- Token URL: `https://${config.subdomain}.onelogin.com/auth/oauth2/v2/token`
- Required config: `subdomain`, `client_id`, `client_secret`
- Scoped config: `user_ids`, `role_ids`, `app_ids`, `privilege_ids`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error`, `auth_error`, `rate_limit`, `schema_drift`

## Runtime output

- Adapter package: `sources/onelogin`
- Health endpoint: `/source-runtimes/health?source_id=onelogin`
- Source health receipt: `sources/onelogin/source_health_receipt.json`
- EvidenceCAS reference kind: `onelogin.evidence_cas_reference`

## Families

- `users`, emits `onelogin.users`, reads `/api/2/users`, projects identity users.
- `groups`, emits `onelogin.groups`, reads `/api/1/groups`, projects identity groups.
- `roles`, emits `onelogin.roles`, reads `/api/2/roles`, projects roles as identity groups.
- `apps`, emits `onelogin.apps`, reads `/api/2/apps`, projects identity applications.
- `audit_events`, emits `onelogin.audit_events`, reads `/api/1/events`, projects identity audit activity.
- `privileges`, emits `onelogin.privileges`, reads `/api/1/privileges`, projects delegated admin privilege definitions.
- `mappings`, emits `onelogin.mappings`, reads `/api/2/mappings`, projects policy rules.
- `user_apps`, emits `onelogin.user_apps`, reads `/api/2/users/{user_id}/apps`, projects user app assignments.
- `user_privileges`, emits `onelogin.user_privileges`, reads `/api/2/users/{user_id}/privileges`, projects user privilege assignments.
- `delegated_privileges`, emits `onelogin.delegated_privileges`, reads `/api/2/users/{user_id}/delegated_privileges`, projects delegated privilege assignments.
- `mfa_devices`, emits `onelogin.mfa_devices`, reads `/api/2/mfa/users/{user_id}/devices`, projects user-owned credentials.
- `role_users`, emits `onelogin.role_users`, reads `/api/2/roles/{role_id}/users`, projects role membership.
- `role_admins`, emits `onelogin.role_admins`, reads `/api/2/roles/{role_id}/admins`, projects role admin assignments.
- `role_apps`, emits `onelogin.role_apps`, reads `/api/2/roles/{role_id}/apps`, projects role app assignments.
- `app_users`, emits `onelogin.app_users`, reads `/api/2/apps/{app_id}/users`, projects app user assignments.
- `app_rules`, emits `onelogin.app_rules`, reads `/api/2/apps/{app_id}/rules`, projects app policy rules.
- `privilege_users`, emits `onelogin.privilege_users`, reads `/api/1/privileges/{privilege_id}/users`, projects privilege user assignments.
- `privilege_roles`, emits `onelogin.privilege_roles`, reads `/api/1/privileges/{privilege_id}/roles`, projects privilege role assignments.

## Runtime Notes

- V2 collection endpoints use OneLogin `After-Cursor` response headers with `cursor` request parameters.
- V1 collection endpoints use provider response cursors with `after_cursor` request parameters.
- Scoped families require configured parent IDs for bounded fanout. `deploy.yaml` wires `ONELOGIN_USER_IDS`, `ONELOGIN_ROLE_IDS`, `ONELOGIN_APP_IDS`, and `ONELOGIN_PRIVILEGE_IDS`.

## Tests

- `go test ./sources/internal/jsonapi ./sources/onelogin ./internal/sourceprojection -count=1`
- `make catalog-check`
- `make connector-catalog-fidelity-check`
