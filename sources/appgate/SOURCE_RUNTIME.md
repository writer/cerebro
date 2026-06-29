# Appgate

Generated Source Runtime SDK scaffold for `appgate`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/appgate`
- Health endpoint: `/source-runtimes/health?source_id=appgate`
- Source health receipt: `sources/appgate/source_health_receipt.json`
- EvidenceCAS reference kind: `appgate.evidence_cas_reference`

## Families

- `users`, emits `appgate.users`, reads `/v1/users`
- `groups`, emits `appgate.groups`, reads `/v1/groups`
- `roles`, emits `appgate.roles`, reads `/v1/roles`
- `applications`, emits `appgate.applications`, reads `/v1/applications`
- `audit_events`, emits `appgate.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/appgate ./internal/sourceprojection -count=1`
- `make catalog-check`
