# dbt Cloud

Generated Source Runtime SDK scaffold for `dbt_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/dbt_cloud`
- Health endpoint: `/source-runtimes/health?source_id=dbt_cloud`
- Source health receipt: `sources/dbt_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `dbt_cloud.evidence_cas_reference`

## Families

- `users`, emits `dbt_cloud.users`, reads `/v1/users`
- `accounts`, emits `dbt_cloud.accounts`, reads `/v1/accounts`
- `records`, emits `dbt_cloud.records`, reads `/v1/records`
- `policies`, emits `dbt_cloud.policies`, reads `/v1/policies`
- `audit_events`, emits `dbt_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/dbt_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
