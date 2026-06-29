# Jamf Protect

Generated Source Runtime SDK scaffold for `jamf_protect`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/jamf_protect`
- Health endpoint: `/source-runtimes/health?source_id=jamf_protect`
- Source health receipt: `sources/jamf_protect/source_health_receipt.json`
- EvidenceCAS reference kind: `jamf_protect.evidence_cas_reference`

## Families

- `users`, emits `jamf_protect.users`, reads `/v1/users`
- `groups`, emits `jamf_protect.groups`, reads `/v1/groups`
- `roles`, emits `jamf_protect.roles`, reads `/v1/roles`
- `applications`, emits `jamf_protect.applications`, reads `/v1/applications`
- `audit_events`, emits `jamf_protect.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/jamf_protect ./internal/sourceprojection -count=1`
- `make catalog-check`
