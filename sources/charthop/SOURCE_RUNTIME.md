# Charthop

Generated Source Runtime SDK scaffold for `charthop`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/charthop`
- Health endpoint: `/source-runtimes/health?source_id=charthop`
- Source health receipt: `sources/charthop/source_health_receipt.json`
- EvidenceCAS reference kind: `charthop.evidence_cas_reference`

## Families

- `users`, emits `charthop.users`, reads `/v1/users`
- `accounts`, emits `charthop.accounts`, reads `/v1/accounts`
- `records`, emits `charthop.records`, reads `/v1/records`
- `policies`, emits `charthop.policies`, reads `/v1/policies`
- `audit_events`, emits `charthop.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/charthop ./internal/sourceprojection -count=1`
- `make catalog-check`
