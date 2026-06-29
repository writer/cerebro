# Jamf Pro

Generated Source Runtime SDK scaffold for `jamf_pro`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/jamf_pro`
- Health endpoint: `/source-runtimes/health?source_id=jamf_pro`
- Source health receipt: `sources/jamf_pro/source_health_receipt.json`
- EvidenceCAS reference kind: `jamf_pro.evidence_cas_reference`

## Families

- `users`, emits `jamf_pro.users`, reads `/v1/users`
- `groups`, emits `jamf_pro.groups`, reads `/v1/groups`
- `roles`, emits `jamf_pro.roles`, reads `/v1/roles`
- `applications`, emits `jamf_pro.applications`, reads `/v1/applications`
- `audit_events`, emits `jamf_pro.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/jamf_pro ./internal/sourceprojection -count=1`
- `make catalog-check`
