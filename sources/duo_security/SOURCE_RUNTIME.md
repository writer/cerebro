# Duo Security

Duo Security uses the JSON API Source CDK with Duo Admin API request signing. The adapter signs each request with the configured integration key and secret key and reads Duo Admin API v1/v2/v3 endpoints.

## Runtime Input

- Source type: `json_api`
- Auth model: `duo_hmac` for Admin API v1/v2 families
- Auth model: `duo_hmac_v5` for Admin API v3 integrations
- Base URL: `base_url`, for example `https://api-XXXXXXXX.duosecurity.com`
- Health path: `/admin/v1/users`
- Log windows: `mintime` and `maxtime` are required for activity and authentication log families
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

The shared `duo_hmac` adapter signs requests with SHA-512 to match the provider-owned Go client behavior already covered by `sources/internal/jsonapi` tests. Duo's Admin API documentation still describes the legacy SHA-1 walkthrough, so live tenant smoke tests should keep this auth path on the release checklist.

## Families

- `users`: `GET /admin/v1/users`, emits `duo_security.users`
- `groups`: `GET /admin/v1/groups`, emits `duo_security.groups`
- `administrators`: `GET /admin/v1/admins`, emits `duo_security.administrators`
- `phones`: `GET /admin/v1/phones`, emits `duo_security.phones`
- `hardware_tokens`: `GET /admin/v1/tokens`, emits `duo_security.hardware_tokens`
- `webauthn_credentials`: `GET /admin/v1/webauthncredentials`, emits `duo_security.webauthn_credentials`
- `bypass_codes`: `GET /admin/v1/bypass_codes`, emits `duo_security.bypass_codes`
- `endpoints`: `GET /admin/v1/endpoints`, emits `duo_security.endpoints`
- `roles`: `GET /admin/v1/admin_roles`, emits `duo_security.roles`
- `applications`: `GET /admin/v3/integrations`, emits `duo_security.applications`
- `audit_events`: `GET /admin/v2/logs/activity`, emits `duo_security.audit_events`
- `authentication_logs`: `GET /admin/v2/logs/authentication`, emits `duo_security.authentication_logs`

## Graph Projection

- Users, groups, and administrators project as identity graph nodes.
- Phones, hardware tokens, and WebAuthn credentials project as Duo MFA factor nodes and link to users when the user ID is present.
- Endpoints project as Duo endpoint nodes.
- Applications project as runtime assets.
- Roles and bypass codes project as policy or sensitive runtime records.
- Activity and authentication logs project as audit event context.

## Tests

- `go test ./sources/duo_security ./internal/sourceprojection -count=1`
- `go run ./tools/catalogcheck`
