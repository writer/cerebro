# Authentik Cloud

Source Runtime SDK package for `authentik_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/authentik_cloud`
- Health endpoint: `/source-runtimes/health?source_id=authentik_cloud`
- Source health receipt: `sources/authentik_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `authentik_cloud.evidence_cas_reference`

## Families

- `users`, emits `authentik_cloud.users`, reads `/api/v3/core/users/`
- `groups`, emits `authentik_cloud.groups`, reads `/api/v3/core/groups/`
- `roles`, emits `authentik_cloud.roles`, reads `/api/v3/rbac/roles/`
- `applications`, emits `authentik_cloud.applications`, reads `/api/v3/core/applications/`
- `audit_events`, emits `authentik_cloud.audit_events`, reads `/api/v3/events/events/`

## Tests

- `go test ./sources/authentik_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
