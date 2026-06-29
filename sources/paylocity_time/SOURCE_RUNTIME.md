# Paylocity Time

Generated Source Runtime SDK scaffold for `paylocity_time`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/paylocity_time`
- Health endpoint: `/source-runtimes/health?source_id=paylocity_time`
- Source health receipt: `sources/paylocity_time/source_health_receipt.json`
- EvidenceCAS reference kind: `paylocity_time.evidence_cas_reference`

## Families

- `users`, emits `paylocity_time.users`, reads `/v1/users`
- `accounts`, emits `paylocity_time.accounts`, reads `/v1/accounts`
- `records`, emits `paylocity_time.records`, reads `/v1/records`
- `policies`, emits `paylocity_time.policies`, reads `/v1/policies`
- `audit_events`, emits `paylocity_time.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/paylocity_time ./internal/sourceprojection -count=1`
- `make catalog-check`
