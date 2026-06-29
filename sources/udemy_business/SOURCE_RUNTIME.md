# Udemy Business

Generated Source Runtime SDK scaffold for `udemy_business`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/udemy_business`
- Health endpoint: `/source-runtimes/health?source_id=udemy_business`
- Source health receipt: `sources/udemy_business/source_health_receipt.json`
- EvidenceCAS reference kind: `udemy_business.evidence_cas_reference`

## Families

- `users`, emits `udemy_business.users`, reads `/v1/users`
- `accounts`, emits `udemy_business.accounts`, reads `/v1/accounts`
- `records`, emits `udemy_business.records`, reads `/v1/records`
- `policies`, emits `udemy_business.policies`, reads `/v1/policies`
- `audit_events`, emits `udemy_business.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/udemy_business ./internal/sourceprojection -count=1`
- `make catalog-check`
