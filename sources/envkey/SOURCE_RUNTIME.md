# Envkey

Generated Source Runtime SDK scaffold for `envkey`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/envkey`
- Health endpoint: `/source-runtimes/health?source_id=envkey`
- Source health receipt: `sources/envkey/source_health_receipt.json`
- EvidenceCAS reference kind: `envkey.evidence_cas_reference`

## Families

- `users`, emits `envkey.users`, reads `/v1/users`
- `groups`, emits `envkey.groups`, reads `/v1/groups`
- `roles`, emits `envkey.roles`, reads `/v1/roles`
- `applications`, emits `envkey.applications`, reads `/v1/applications`
- `audit_events`, emits `envkey.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/envkey ./internal/sourceprojection -count=1`
- `make catalog-check`
