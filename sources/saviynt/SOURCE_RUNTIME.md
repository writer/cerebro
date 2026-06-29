# Saviynt

Generated Source Runtime SDK scaffold for `saviynt`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/saviynt`
- Health endpoint: `/source-runtimes/health?source_id=saviynt`
- Source health receipt: `sources/saviynt/source_health_receipt.json`
- EvidenceCAS reference kind: `saviynt.evidence_cas_reference`

## Families

- `users`, emits `saviynt.users`, reads `/v1/users`
- `groups`, emits `saviynt.groups`, reads `/v1/groups`
- `roles`, emits `saviynt.roles`, reads `/v1/roles`
- `applications`, emits `saviynt.applications`, reads `/v1/applications`
- `audit_events`, emits `saviynt.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/saviynt ./internal/sourceprojection -count=1`
- `make catalog-check`
