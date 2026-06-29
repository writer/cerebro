# Device42

Generated Source Runtime SDK scaffold for `device42`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/device42`
- Health endpoint: `/source-runtimes/health?source_id=device42`
- Source health receipt: `sources/device42/source_health_receipt.json`
- EvidenceCAS reference kind: `device42.evidence_cas_reference`

## Families

- `users`, emits `device42.users`, reads `/v1/users`
- `groups`, emits `device42.groups`, reads `/v1/groups`
- `roles`, emits `device42.roles`, reads `/v1/roles`
- `applications`, emits `device42.applications`, reads `/v1/applications`
- `audit_events`, emits `device42.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/device42 ./internal/sourceprojection -count=1`
- `make catalog-check`
