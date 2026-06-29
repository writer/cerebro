# Paycom

Generated Source Runtime SDK scaffold for `paycom`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/paycom`
- Health endpoint: `/source-runtimes/health?source_id=paycom`
- Source health receipt: `sources/paycom/source_health_receipt.json`
- EvidenceCAS reference kind: `paycom.evidence_cas_reference`

## Families

- `users`, emits `paycom.users`, reads `/v1/users`
- `accounts`, emits `paycom.accounts`, reads `/v1/accounts`
- `records`, emits `paycom.records`, reads `/v1/records`
- `policies`, emits `paycom.policies`, reads `/v1/policies`
- `audit_events`, emits `paycom.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/paycom ./internal/sourceprojection -count=1`
- `make catalog-check`
