# Duo Source Runtime

## Provider API

- Provider: Duo Admin API
- Base URL: `https://api-XXXXXXXX.duosecurity.com`
- Authentication:
  - `duo_hmac` for Admin API v1 and v2 families
  - `duo_hmac_v5` for Admin API v3 integrations
- References:
  - https://duo.com/docs/adminapi
  - https://github.com/duosecurity/duo_client_python/blob/master/duo_client/admin.py
  - https://github.com/duosecurity/duo_api_golang/blob/master/duoapi.go

## Families

- `user`: `GET /admin/v1/users`, emits `duo.user`
- `group`: `GET /admin/v1/groups`, emits `duo.group`
- `administrator`: `GET /admin/v1/admins`, emits `duo.administrator`
- `endpoint`: `GET /admin/v1/endpoints`, emits `duo.endpoint`
- `phone`: `GET /admin/v1/phones`, emits `duo.phone`
- `token`: `GET /admin/v1/tokens`, emits `duo.token`
- `web_authn_credential`: `GET /admin/v1/webauthncredentials`, emits `duo.web_authn_credential`
- `role`: `GET /admin/v1/admin_roles`, emits `duo.role`
- `application`: `GET /admin/v3/integrations`, emits `duo.application`
- `audit_event`: `GET /admin/v2/logs/activity`, emits `duo.audit_event`
- `authentication_log`: `GET /admin/v2/logs/authentication`, emits `duo.authentication_log`

## Runtime Notes

- Inventory families use Duo offset pagination with `limit` and `offset`.
- Activity and authentication log families use `next_offset` cursors returned under `response.metadata.next_offset`.
- Log runtimes should provide `mintime` and `maxtime` in milliseconds to bound each sync window.

## Validation

- `go test ./sources/duo ./sources/internal/jsonapi ./internal/sourceprojection -count=1`
- `go test ./internal/sourceregistry ./internal/connectorcatalog ./sources/internal/catalogruntime ./internal/connectordefinitions ./tools/catalogcheck ./internal/sourcecdk -count=1`
