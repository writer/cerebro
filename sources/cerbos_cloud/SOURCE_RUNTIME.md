# Cerbos Cloud

Generated Source Runtime SDK scaffold for `cerbos_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cerbos_cloud`
- Health endpoint: `/source-runtimes/health?source_id=cerbos_cloud`
- Source health receipt: `sources/cerbos_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `cerbos_cloud.evidence_cas_reference`

## Families

- `users`, emits `cerbos_cloud.users`, reads `/v1/users`
- `groups`, emits `cerbos_cloud.groups`, reads `/v1/groups`
- `roles`, emits `cerbos_cloud.roles`, reads `/v1/roles`
- `applications`, emits `cerbos_cloud.applications`, reads `/v1/applications`
- `audit_events`, emits `cerbos_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cerbos_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
