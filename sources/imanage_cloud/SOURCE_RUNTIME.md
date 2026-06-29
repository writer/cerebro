# Imanage Cloud

Generated Source Runtime SDK scaffold for `imanage_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/imanage_cloud`
- Health endpoint: `/source-runtimes/health?source_id=imanage_cloud`
- Source health receipt: `sources/imanage_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `imanage_cloud.evidence_cas_reference`

## Families

- `users`, emits `imanage_cloud.users`, reads `/v1/users`
- `accounts`, emits `imanage_cloud.accounts`, reads `/v1/accounts`
- `records`, emits `imanage_cloud.records`, reads `/v1/records`
- `policies`, emits `imanage_cloud.policies`, reads `/v1/policies`
- `audit_events`, emits `imanage_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/imanage_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
