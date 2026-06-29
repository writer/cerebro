# Mosyle

Generated Source Runtime SDK scaffold for `mosyle`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mosyle`
- Health endpoint: `/source-runtimes/health?source_id=mosyle`
- Source health receipt: `sources/mosyle/source_health_receipt.json`
- EvidenceCAS reference kind: `mosyle.evidence_cas_reference`

## Families

- `users`, emits `mosyle.users`, reads `/v1/users`
- `groups`, emits `mosyle.groups`, reads `/v1/groups`
- `roles`, emits `mosyle.roles`, reads `/v1/roles`
- `applications`, emits `mosyle.applications`, reads `/v1/applications`
- `audit_events`, emits `mosyle.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/mosyle ./internal/sourceprojection -count=1`
- `make catalog-check`
