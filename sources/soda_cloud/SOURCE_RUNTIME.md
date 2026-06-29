# Soda Cloud

Generated Source Runtime SDK scaffold for `soda_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/soda_cloud`
- Health endpoint: `/source-runtimes/health?source_id=soda_cloud`
- Source health receipt: `sources/soda_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `soda_cloud.evidence_cas_reference`

## Families

- `users`, emits `soda_cloud.users`, reads `/v1/users`
- `accounts`, emits `soda_cloud.accounts`, reads `/v1/accounts`
- `records`, emits `soda_cloud.records`, reads `/v1/records`
- `policies`, emits `soda_cloud.policies`, reads `/v1/policies`
- `audit_events`, emits `soda_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/soda_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
