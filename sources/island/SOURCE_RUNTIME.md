# Island

Generated Source Runtime SDK scaffold for `island`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/island`
- Health endpoint: `/source-runtimes/health?source_id=island`
- Source health receipt: `sources/island/source_health_receipt.json`
- EvidenceCAS reference kind: `island.evidence_cas_reference`

## Families

- `users`, emits `island.users`, reads `/v1/users`
- `groups`, emits `island.groups`, reads `/v1/groups`
- `roles`, emits `island.roles`, reads `/v1/roles`
- `applications`, emits `island.applications`, reads `/v1/applications`
- `audit_events`, emits `island.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/island ./internal/sourceprojection -count=1`
- `make catalog-check`
