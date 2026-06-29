# Bettercloud

Generated Source Runtime SDK scaffold for `bettercloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bettercloud`
- Health endpoint: `/source-runtimes/health?source_id=bettercloud`
- Source health receipt: `sources/bettercloud/source_health_receipt.json`
- EvidenceCAS reference kind: `bettercloud.evidence_cas_reference`

## Families

- `users`, emits `bettercloud.users`, reads `/v1/users`
- `groups`, emits `bettercloud.groups`, reads `/v1/groups`
- `roles`, emits `bettercloud.roles`, reads `/v1/roles`
- `applications`, emits `bettercloud.applications`, reads `/v1/applications`
- `audit_events`, emits `bettercloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/bettercloud ./internal/sourceprojection -count=1`
- `make catalog-check`
