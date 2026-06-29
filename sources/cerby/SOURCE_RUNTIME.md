# Cerby

Generated Source Runtime SDK scaffold for `cerby`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cerby`
- Health endpoint: `/source-runtimes/health?source_id=cerby`
- Source health receipt: `sources/cerby/source_health_receipt.json`
- EvidenceCAS reference kind: `cerby.evidence_cas_reference`

## Families

- `users`, emits `cerby.users`, reads `/v1/users`
- `groups`, emits `cerby.groups`, reads `/v1/groups`
- `roles`, emits `cerby.roles`, reads `/v1/roles`
- `applications`, emits `cerby.applications`, reads `/v1/applications`
- `audit_events`, emits `cerby.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cerby ./internal/sourceprojection -count=1`
- `make catalog-check`
