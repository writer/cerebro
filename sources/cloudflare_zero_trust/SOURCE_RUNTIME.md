# Cloudflare Zero Trust

Generated Source Runtime SDK scaffold for `cloudflare_zero_trust`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cloudflare_zero_trust`
- Health endpoint: `/source-runtimes/health?source_id=cloudflare_zero_trust`
- Source health receipt: `sources/cloudflare_zero_trust/source_health_receipt.json`
- EvidenceCAS reference kind: `cloudflare_zero_trust.evidence_cas_reference`

## Families

- `users`, emits `cloudflare_zero_trust.users`, reads `/v1/users`
- `groups`, emits `cloudflare_zero_trust.groups`, reads `/v1/groups`
- `roles`, emits `cloudflare_zero_trust.roles`, reads `/v1/roles`
- `applications`, emits `cloudflare_zero_trust.applications`, reads `/v1/applications`
- `audit_events`, emits `cloudflare_zero_trust.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cloudflare_zero_trust ./internal/sourceprojection -count=1`
- `make catalog-check`
