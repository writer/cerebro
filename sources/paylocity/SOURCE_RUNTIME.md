# Paylocity

Generated Source Runtime SDK scaffold for `paylocity`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/paylocity`
- Health endpoint: `/source-runtimes/health?source_id=paylocity`
- Source health receipt: `sources/paylocity/source_health_receipt.json`
- EvidenceCAS reference kind: `paylocity.evidence_cas_reference`

## Families

- `users`, emits `paylocity.users`, reads `/v1/users`
- `accounts`, emits `paylocity.accounts`, reads `/v1/accounts`
- `records`, emits `paylocity.records`, reads `/v1/records`
- `policies`, emits `paylocity.policies`, reads `/v1/policies`
- `audit_events`, emits `paylocity.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/paylocity ./internal/sourceprojection -count=1`
- `make catalog-check`
