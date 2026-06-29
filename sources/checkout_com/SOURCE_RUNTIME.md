# Checkout.com

Generated Source Runtime SDK scaffold for `checkout_com`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/checkout_com`
- Health endpoint: `/source-runtimes/health?source_id=checkout_com`
- Source health receipt: `sources/checkout_com/source_health_receipt.json`
- EvidenceCAS reference kind: `checkout_com.evidence_cas_reference`

## Families

- `users`, emits `checkout_com.users`, reads `/v1/users`
- `accounts`, emits `checkout_com.accounts`, reads `/v1/accounts`
- `records`, emits `checkout_com.records`, reads `/v1/records`
- `policies`, emits `checkout_com.policies`, reads `/v1/policies`
- `audit_events`, emits `checkout_com.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/checkout_com ./internal/sourceprojection -count=1`
- `make catalog-check`
