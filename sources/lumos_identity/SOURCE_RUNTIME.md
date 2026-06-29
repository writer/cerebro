# Lumos Identity

Generated Source Runtime SDK scaffold for `lumos_identity`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/lumos_identity`
- Health endpoint: `/source-runtimes/health?source_id=lumos_identity`
- Source health receipt: `sources/lumos_identity/source_health_receipt.json`
- EvidenceCAS reference kind: `lumos_identity.evidence_cas_reference`

## Families

- `users`, emits `lumos_identity.users`, reads `/v1/users`
- `groups`, emits `lumos_identity.groups`, reads `/v1/groups`
- `roles`, emits `lumos_identity.roles`, reads `/v1/roles`
- `applications`, emits `lumos_identity.applications`, reads `/v1/applications`
- `audit_events`, emits `lumos_identity.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/lumos_identity ./internal/sourceprojection -count=1`
- `make catalog-check`
