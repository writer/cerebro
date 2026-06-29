# Customer.io

Generated Source Runtime SDK scaffold for `customer_io`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/customer_io`
- Health endpoint: `/source-runtimes/health?source_id=customer_io`
- Source health receipt: `sources/customer_io/source_health_receipt.json`
- EvidenceCAS reference kind: `customer_io.evidence_cas_reference`

## Families

- `users`, emits `customer_io.users`, reads `/v1/users`
- `accounts`, emits `customer_io.accounts`, reads `/v1/accounts`
- `records`, emits `customer_io.records`, reads `/v1/records`
- `policies`, emits `customer_io.policies`, reads `/v1/policies`
- `audit_events`, emits `customer_io.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/customer_io ./internal/sourceprojection -count=1`
- `make catalog-check`
