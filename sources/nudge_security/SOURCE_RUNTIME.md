# Nudge Security

Generated Source Runtime SDK scaffold for `nudge_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/nudge_security`
- Health endpoint: `/source-runtimes/health?source_id=nudge_security`
- Source health receipt: `sources/nudge_security/source_health_receipt.json`
- EvidenceCAS reference kind: `nudge_security.evidence_cas_reference`

## Families

- `users`, emits `nudge_security.users`, reads `/v1/users`
- `groups`, emits `nudge_security.groups`, reads `/v1/groups`
- `roles`, emits `nudge_security.roles`, reads `/v1/roles`
- `applications`, emits `nudge_security.applications`, reads `/v1/applications`
- `audit_events`, emits `nudge_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/nudge_security ./internal/sourceprojection -count=1`
- `make catalog-check`
