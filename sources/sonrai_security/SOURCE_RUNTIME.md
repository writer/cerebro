# Sonrai Security

Generated Source Runtime SDK scaffold for `sonrai_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sonrai_security`
- Health endpoint: `/source-runtimes/health?source_id=sonrai_security`
- Source health receipt: `sources/sonrai_security/source_health_receipt.json`
- EvidenceCAS reference kind: `sonrai_security.evidence_cas_reference`

## Families

- `users`, emits `sonrai_security.users`, reads `/v1/users`
- `groups`, emits `sonrai_security.groups`, reads `/v1/groups`
- `roles`, emits `sonrai_security.roles`, reads `/v1/roles`
- `applications`, emits `sonrai_security.applications`, reads `/v1/applications`
- `audit_events`, emits `sonrai_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sonrai_security ./internal/sourceprojection -count=1`
- `make catalog-check`
