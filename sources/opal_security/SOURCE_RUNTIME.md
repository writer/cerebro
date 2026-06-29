# Opal Security

Generated Source Runtime SDK scaffold for `opal_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/opal_security`
- Health endpoint: `/source-runtimes/health?source_id=opal_security`
- Source health receipt: `sources/opal_security/source_health_receipt.json`
- EvidenceCAS reference kind: `opal_security.evidence_cas_reference`

## Families

- `users`, emits `opal_security.users`, reads `/v1/users`
- `groups`, emits `opal_security.groups`, reads `/v1/groups`
- `roles`, emits `opal_security.roles`, reads `/v1/roles`
- `applications`, emits `opal_security.applications`, reads `/v1/applications`
- `audit_events`, emits `opal_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/opal_security ./internal/sourceprojection -count=1`
- `make catalog-check`
