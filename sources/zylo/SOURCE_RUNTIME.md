# Zylo

Generated Source Runtime SDK scaffold for `zylo`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zylo`
- Health endpoint: `/source-runtimes/health?source_id=zylo`
- Source health receipt: `sources/zylo/source_health_receipt.json`
- EvidenceCAS reference kind: `zylo.evidence_cas_reference`

## Families

- `users`, emits `zylo.users`, reads `/v1/users`
- `groups`, emits `zylo.groups`, reads `/v1/groups`
- `roles`, emits `zylo.roles`, reads `/v1/roles`
- `applications`, emits `zylo.applications`, reads `/v1/applications`
- `audit_events`, emits `zylo.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zylo ./internal/sourceprojection -count=1`
- `make catalog-check`
