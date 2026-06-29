# Portable

Generated Source Runtime SDK scaffold for `portable`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/portable`
- Health endpoint: `/source-runtimes/health?source_id=portable`
- Source health receipt: `sources/portable/source_health_receipt.json`
- EvidenceCAS reference kind: `portable.evidence_cas_reference`

## Families

- `users`, emits `portable.users`, reads `/v1/users`
- `accounts`, emits `portable.accounts`, reads `/v1/accounts`
- `records`, emits `portable.records`, reads `/v1/records`
- `policies`, emits `portable.policies`, reads `/v1/policies`
- `audit_events`, emits `portable.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/portable ./internal/sourceprojection -count=1`
- `make catalog-check`
