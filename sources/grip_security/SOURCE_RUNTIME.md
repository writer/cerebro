# Grip Security

Generated Source Runtime SDK scaffold for `grip_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/grip_security`
- Health endpoint: `/source-runtimes/health?source_id=grip_security`
- Source health receipt: `sources/grip_security/source_health_receipt.json`
- EvidenceCAS reference kind: `grip_security.evidence_cas_reference`

## Families

- `users`, emits `grip_security.users`, reads `/v1/users`
- `groups`, emits `grip_security.groups`, reads `/v1/groups`
- `roles`, emits `grip_security.roles`, reads `/v1/roles`
- `applications`, emits `grip_security.applications`, reads `/v1/applications`
- `audit_events`, emits `grip_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/grip_security ./internal/sourceprojection -count=1`
- `make catalog-check`
