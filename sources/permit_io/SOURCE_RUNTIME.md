# Permit.io

Generated Source Runtime SDK scaffold for `permit_io`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/permit_io`
- Health endpoint: `/source-runtimes/health?source_id=permit_io`
- Source health receipt: `sources/permit_io/source_health_receipt.json`
- EvidenceCAS reference kind: `permit_io.evidence_cas_reference`

## Families

- `users`, emits `permit_io.users`, reads `/v1/users`
- `groups`, emits `permit_io.groups`, reads `/v1/groups`
- `roles`, emits `permit_io.roles`, reads `/v1/roles`
- `applications`, emits `permit_io.applications`, reads `/v1/applications`
- `audit_events`, emits `permit_io.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/permit_io ./internal/sourceprojection -count=1`
- `make catalog-check`
