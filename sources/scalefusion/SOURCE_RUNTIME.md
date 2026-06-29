# Scalefusion

Generated Source Runtime SDK scaffold for `scalefusion`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/scalefusion`
- Health endpoint: `/source-runtimes/health?source_id=scalefusion`
- Source health receipt: `sources/scalefusion/source_health_receipt.json`
- EvidenceCAS reference kind: `scalefusion.evidence_cas_reference`

## Families

- `users`, emits `scalefusion.users`, reads `/v1/users`
- `groups`, emits `scalefusion.groups`, reads `/v1/groups`
- `roles`, emits `scalefusion.roles`, reads `/v1/roles`
- `applications`, emits `scalefusion.applications`, reads `/v1/applications`
- `audit_events`, emits `scalefusion.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/scalefusion ./internal/sourceprojection -count=1`
- `make catalog-check`
