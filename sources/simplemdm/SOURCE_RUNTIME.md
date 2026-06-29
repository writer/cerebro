# Simplemdm

Generated Source Runtime SDK scaffold for `simplemdm`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/simplemdm`
- Health endpoint: `/source-runtimes/health?source_id=simplemdm`
- Source health receipt: `sources/simplemdm/source_health_receipt.json`
- EvidenceCAS reference kind: `simplemdm.evidence_cas_reference`

## Families

- `users`, emits `simplemdm.users`, reads `/v1/users`
- `groups`, emits `simplemdm.groups`, reads `/v1/groups`
- `roles`, emits `simplemdm.roles`, reads `/v1/roles`
- `applications`, emits `simplemdm.applications`, reads `/v1/applications`
- `audit_events`, emits `simplemdm.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/simplemdm ./internal/sourceprojection -count=1`
- `make catalog-check`
