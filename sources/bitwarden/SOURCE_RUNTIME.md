# Bitwarden

Generated Source Runtime SDK scaffold for `bitwarden`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bitwarden`
- Health endpoint: `/source-runtimes/health?source_id=bitwarden`
- Source health receipt: `sources/bitwarden/source_health_receipt.json`
- EvidenceCAS reference kind: `bitwarden.evidence_cas_reference`

## Families

- `users`, emits `bitwarden.users`, reads `/v1/users`
- `groups`, emits `bitwarden.groups`, reads `/v1/groups`
- `roles`, emits `bitwarden.roles`, reads `/v1/roles`
- `applications`, emits `bitwarden.applications`, reads `/v1/applications`
- `audit_events`, emits `bitwarden.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/bitwarden ./internal/sourceprojection -count=1`
- `make catalog-check`
