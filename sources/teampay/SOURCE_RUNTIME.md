# Teampay

Generated Source Runtime SDK scaffold for `teampay`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/teampay`
- Health endpoint: `/source-runtimes/health?source_id=teampay`
- Source health receipt: `sources/teampay/source_health_receipt.json`
- EvidenceCAS reference kind: `teampay.evidence_cas_reference`

## Families

- `users`, emits `teampay.users`, reads `/v1/users`
- `accounts`, emits `teampay.accounts`, reads `/v1/accounts`
- `records`, emits `teampay.records`, reads `/v1/records`
- `policies`, emits `teampay.policies`, reads `/v1/policies`
- `audit_events`, emits `teampay.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/teampay ./internal/sourceprojection -count=1`
- `make catalog-check`
