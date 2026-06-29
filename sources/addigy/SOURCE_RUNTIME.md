# Addigy

Generated Source Runtime SDK scaffold for `addigy`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/addigy`
- Health endpoint: `/source-runtimes/health?source_id=addigy`
- Source health receipt: `sources/addigy/source_health_receipt.json`
- EvidenceCAS reference kind: `addigy.evidence_cas_reference`

## Families

- `users`, emits `addigy.users`, reads `/v1/users`
- `groups`, emits `addigy.groups`, reads `/v1/groups`
- `roles`, emits `addigy.roles`, reads `/v1/roles`
- `applications`, emits `addigy.applications`, reads `/v1/applications`
- `audit_events`, emits `addigy.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/addigy ./internal/sourceprojection -count=1`
- `make catalog-check`
