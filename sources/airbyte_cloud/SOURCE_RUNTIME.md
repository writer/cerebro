# Airbyte Cloud

Generated Source Runtime SDK scaffold for `airbyte_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/airbyte_cloud`
- Health endpoint: `/source-runtimes/health?source_id=airbyte_cloud`
- Source health receipt: `sources/airbyte_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `airbyte_cloud.evidence_cas_reference`

## Families

- `users`, emits `airbyte_cloud.users`, reads `/v1/users`
- `accounts`, emits `airbyte_cloud.accounts`, reads `/v1/accounts`
- `records`, emits `airbyte_cloud.records`, reads `/v1/records`
- `policies`, emits `airbyte_cloud.policies`, reads `/v1/policies`
- `audit_events`, emits `airbyte_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/airbyte_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
