# Miradore

Generated Source Runtime SDK scaffold for `miradore`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/miradore`
- Health endpoint: `/source-runtimes/health?source_id=miradore`
- Source health receipt: `sources/miradore/source_health_receipt.json`
- EvidenceCAS reference kind: `miradore.evidence_cas_reference`

## Families

- `users`, emits `miradore.users`, reads `/v1/users`
- `groups`, emits `miradore.groups`, reads `/v1/groups`
- `roles`, emits `miradore.roles`, reads `/v1/roles`
- `applications`, emits `miradore.applications`, reads `/v1/applications`
- `audit_events`, emits `miradore.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/miradore ./internal/sourceprojection -count=1`
- `make catalog-check`
