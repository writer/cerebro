# Zilla Security

Generated Source Runtime SDK scaffold for `zilla_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zilla_security`
- Health endpoint: `/source-runtimes/health?source_id=zilla_security`
- Source health receipt: `sources/zilla_security/source_health_receipt.json`
- EvidenceCAS reference kind: `zilla_security.evidence_cas_reference`

## Families

- `users`, emits `zilla_security.users`, reads `/v1/users`
- `groups`, emits `zilla_security.groups`, reads `/v1/groups`
- `roles`, emits `zilla_security.roles`, reads `/v1/roles`
- `applications`, emits `zilla_security.applications`, reads `/v1/applications`
- `audit_events`, emits `zilla_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zilla_security ./internal/sourceprojection -count=1`
- `make catalog-check`
