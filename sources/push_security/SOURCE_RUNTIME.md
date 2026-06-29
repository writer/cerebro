# Push Security

Generated Source Runtime SDK scaffold for `push_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/push_security`
- Health endpoint: `/source-runtimes/health?source_id=push_security`
- Source health receipt: `sources/push_security/source_health_receipt.json`
- EvidenceCAS reference kind: `push_security.evidence_cas_reference`

## Families

- `users`, emits `push_security.users`, reads `/v1/users`
- `groups`, emits `push_security.groups`, reads `/v1/groups`
- `roles`, emits `push_security.roles`, reads `/v1/roles`
- `applications`, emits `push_security.applications`, reads `/v1/applications`
- `audit_events`, emits `push_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/push_security ./internal/sourceprojection -count=1`
- `make catalog-check`
