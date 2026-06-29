# Cyolo

Generated Source Runtime SDK scaffold for `cyolo`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cyolo`
- Health endpoint: `/source-runtimes/health?source_id=cyolo`
- Source health receipt: `sources/cyolo/source_health_receipt.json`
- EvidenceCAS reference kind: `cyolo.evidence_cas_reference`

## Families

- `users`, emits `cyolo.users`, reads `/v1/users`
- `groups`, emits `cyolo.groups`, reads `/v1/groups`
- `roles`, emits `cyolo.roles`, reads `/v1/roles`
- `applications`, emits `cyolo.applications`, reads `/v1/applications`
- `audit_events`, emits `cyolo.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cyolo ./internal/sourceprojection -count=1`
- `make catalog-check`
