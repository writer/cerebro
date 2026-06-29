# Britive

Generated Source Runtime SDK scaffold for `britive`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/britive`
- Health endpoint: `/source-runtimes/health?source_id=britive`
- Source health receipt: `sources/britive/source_health_receipt.json`
- EvidenceCAS reference kind: `britive.evidence_cas_reference`

## Families

- `users`, emits `britive.users`, reads `/v1/users`
- `groups`, emits `britive.groups`, reads `/v1/groups`
- `roles`, emits `britive.roles`, reads `/v1/roles`
- `applications`, emits `britive.applications`, reads `/v1/applications`
- `audit_events`, emits `britive.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/britive ./internal/sourceprojection -count=1`
- `make catalog-check`
