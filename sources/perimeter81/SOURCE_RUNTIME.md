# Perimeter81

Generated Source Runtime SDK scaffold for `perimeter81`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/perimeter81`
- Health endpoint: `/source-runtimes/health?source_id=perimeter81`
- Source health receipt: `sources/perimeter81/source_health_receipt.json`
- EvidenceCAS reference kind: `perimeter81.evidence_cas_reference`

## Families

- `users`, emits `perimeter81.users`, reads `/v1/users`
- `groups`, emits `perimeter81.groups`, reads `/v1/groups`
- `roles`, emits `perimeter81.roles`, reads `/v1/roles`
- `applications`, emits `perimeter81.applications`, reads `/v1/applications`
- `audit_events`, emits `perimeter81.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/perimeter81 ./internal/sourceprojection -count=1`
- `make catalog-check`
