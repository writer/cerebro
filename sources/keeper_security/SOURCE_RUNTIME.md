# Keeper Security

Generated Source Runtime SDK scaffold for `keeper_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/keeper_security`
- Health endpoint: `/source-runtimes/health?source_id=keeper_security`
- Source health receipt: `sources/keeper_security/source_health_receipt.json`
- EvidenceCAS reference kind: `keeper_security.evidence_cas_reference`

## Families

- `users`, emits `keeper_security.users`, reads `/v1/users`
- `groups`, emits `keeper_security.groups`, reads `/v1/groups`
- `roles`, emits `keeper_security.roles`, reads `/v1/roles`
- `applications`, emits `keeper_security.applications`, reads `/v1/applications`
- `audit_events`, emits `keeper_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/keeper_security ./internal/sourceprojection -count=1`
- `make catalog-check`
