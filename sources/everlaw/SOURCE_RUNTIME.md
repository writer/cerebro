# Everlaw

Generated Source Runtime SDK scaffold for `everlaw`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/everlaw`
- Health endpoint: `/source-runtimes/health?source_id=everlaw`
- Source health receipt: `sources/everlaw/source_health_receipt.json`
- EvidenceCAS reference kind: `everlaw.evidence_cas_reference`

## Families

- `users`, emits `everlaw.users`, reads `/v1/users`
- `accounts`, emits `everlaw.accounts`, reads `/v1/accounts`
- `records`, emits `everlaw.records`, reads `/v1/records`
- `policies`, emits `everlaw.policies`, reads `/v1/policies`
- `audit_events`, emits `everlaw.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/everlaw ./internal/sourceprojection -count=1`
- `make catalog-check`
