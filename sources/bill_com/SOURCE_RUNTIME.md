# Bill.com

Generated Source Runtime SDK scaffold for `bill_com`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bill_com`
- Health endpoint: `/source-runtimes/health?source_id=bill_com`
- Source health receipt: `sources/bill_com/source_health_receipt.json`
- EvidenceCAS reference kind: `bill_com.evidence_cas_reference`

## Families

- `users`, emits `bill_com.users`, reads `/v1/users`
- `accounts`, emits `bill_com.accounts`, reads `/v1/accounts`
- `records`, emits `bill_com.records`, reads `/v1/records`
- `policies`, emits `bill_com.policies`, reads `/v1/policies`
- `audit_events`, emits `bill_com.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/bill_com ./internal/sourceprojection -count=1`
- `make catalog-check`
