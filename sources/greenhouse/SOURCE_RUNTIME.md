# Greenhouse

Generated Source Runtime SDK scaffold for `greenhouse`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/greenhouse`
- Health endpoint: `/source-runtimes/health?source_id=greenhouse`
- Source health receipt: `sources/greenhouse/source_health_receipt.json`
- EvidenceCAS reference kind: `greenhouse.evidence_cas_reference`

## Families

- `users`, emits `greenhouse.users`, reads `/v1/users`
- `accounts`, emits `greenhouse.accounts`, reads `/v1/accounts`
- `records`, emits `greenhouse.records`, reads `/v1/records`
- `policies`, emits `greenhouse.policies`, reads `/v1/policies`
- `audit_events`, emits `greenhouse.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/greenhouse ./internal/sourceprojection -count=1`
- `make catalog-check`
