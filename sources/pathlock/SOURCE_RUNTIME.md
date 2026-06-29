# Pathlock

Generated Source Runtime SDK scaffold for `pathlock`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/pathlock`
- Health endpoint: `/source-runtimes/health?source_id=pathlock`
- Source health receipt: `sources/pathlock/source_health_receipt.json`
- EvidenceCAS reference kind: `pathlock.evidence_cas_reference`

## Families

- `users`, emits `pathlock.users`, reads `/v1/users`
- `groups`, emits `pathlock.groups`, reads `/v1/groups`
- `roles`, emits `pathlock.roles`, reads `/v1/roles`
- `applications`, emits `pathlock.applications`, reads `/v1/applications`
- `audit_events`, emits `pathlock.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/pathlock ./internal/sourceprojection -count=1`
- `make catalog-check`
