# Dashlane Business

Generated Source Runtime SDK scaffold for `dashlane_business`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/dashlane_business`
- Health endpoint: `/source-runtimes/health?source_id=dashlane_business`
- Source health receipt: `sources/dashlane_business/source_health_receipt.json`
- EvidenceCAS reference kind: `dashlane_business.evidence_cas_reference`

## Families

- `users`, emits `dashlane_business.users`, reads `/v1/users`
- `groups`, emits `dashlane_business.groups`, reads `/v1/groups`
- `roles`, emits `dashlane_business.roles`, reads `/v1/roles`
- `applications`, emits `dashlane_business.applications`, reads `/v1/applications`
- `audit_events`, emits `dashlane_business.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/dashlane_business ./internal/sourceprojection -count=1`
- `make catalog-check`
