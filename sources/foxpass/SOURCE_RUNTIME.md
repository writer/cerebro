# Foxpass

Generated Source Runtime SDK scaffold for `foxpass`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/foxpass`
- Health endpoint: `/source-runtimes/health?source_id=foxpass`
- Source health receipt: `sources/foxpass/source_health_receipt.json`
- EvidenceCAS reference kind: `foxpass.evidence_cas_reference`

## Families

- `users`, emits `foxpass.users`, reads `/v1/users`
- `groups`, emits `foxpass.groups`, reads `/v1/groups`
- `roles`, emits `foxpass.roles`, reads `/v1/roles`
- `applications`, emits `foxpass.applications`, reads `/v1/applications`
- `audit_events`, emits `foxpass.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/foxpass ./internal/sourceprojection -count=1`
- `make catalog-check`
