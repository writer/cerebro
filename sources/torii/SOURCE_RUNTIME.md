# Torii

Generated Source Runtime SDK scaffold for `torii`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/torii`
- Health endpoint: `/source-runtimes/health?source_id=torii`
- Source health receipt: `sources/torii/source_health_receipt.json`
- EvidenceCAS reference kind: `torii.evidence_cas_reference`

## Families

- `users`, emits `torii.users`, reads `/v1/users`
- `groups`, emits `torii.groups`, reads `/v1/groups`
- `roles`, emits `torii.roles`, reads `/v1/roles`
- `applications`, emits `torii.applications`, reads `/v1/applications`
- `audit_events`, emits `torii.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/torii ./internal/sourceprojection -count=1`
- `make catalog-check`
