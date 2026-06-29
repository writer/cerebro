# Genesys Cloud

Generated Source Runtime SDK scaffold for `genesys_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/genesys_cloud`
- Health endpoint: `/source-runtimes/health?source_id=genesys_cloud`
- Source health receipt: `sources/genesys_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `genesys_cloud.evidence_cas_reference`

## Families

- `users`, emits `genesys_cloud.users`, reads `/v1/users`
- `accounts`, emits `genesys_cloud.accounts`, reads `/v1/accounts`
- `records`, emits `genesys_cloud.records`, reads `/v1/records`
- `policies`, emits `genesys_cloud.policies`, reads `/v1/policies`
- `audit_events`, emits `genesys_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/genesys_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
