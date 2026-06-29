# Descope

Generated Source Runtime SDK scaffold for `descope`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/descope`
- Health endpoint: `/source-runtimes/health?source_id=descope`
- Source health receipt: `sources/descope/source_health_receipt.json`
- EvidenceCAS reference kind: `descope.evidence_cas_reference`

## Families

- `users`, emits `descope.users`, reads `/v1/users`
- `groups`, emits `descope.groups`, reads `/v1/groups`
- `roles`, emits `descope.roles`, reads `/v1/roles`
- `applications`, emits `descope.applications`, reads `/v1/applications`
- `audit_events`, emits `descope.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/descope ./internal/sourceprojection -count=1`
- `make catalog-check`
