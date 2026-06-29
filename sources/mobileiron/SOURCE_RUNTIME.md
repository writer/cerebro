# Mobileiron

Generated Source Runtime SDK scaffold for `mobileiron`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mobileiron`
- Health endpoint: `/source-runtimes/health?source_id=mobileiron`
- Source health receipt: `sources/mobileiron/source_health_receipt.json`
- EvidenceCAS reference kind: `mobileiron.evidence_cas_reference`

## Families

- `users`, emits `mobileiron.users`, reads `/v1/users`
- `groups`, emits `mobileiron.groups`, reads `/v1/groups`
- `roles`, emits `mobileiron.roles`, reads `/v1/roles`
- `applications`, emits `mobileiron.applications`, reads `/v1/applications`
- `audit_events`, emits `mobileiron.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/mobileiron ./internal/sourceprojection -count=1`
- `make catalog-check`
