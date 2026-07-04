# Bitwarden

Bitwarden Public API source runtime for `bitwarden`.

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

- `users`, emits `bitwarden.users`, reads `/public/members`
- `groups`, emits `bitwarden.groups`, reads `/public/groups`
- `collections`, emits `bitwarden.collections`, reads `/public/collections`
- `policies`, emits `bitwarden.policies`, reads `/public/policies`
- `audit_events`, emits `bitwarden.audit_events`, reads `/public/events`

## Tests

- `go test ./sources/bitwarden ./internal/sourceprojection -count=1`
- `make catalog-check`
