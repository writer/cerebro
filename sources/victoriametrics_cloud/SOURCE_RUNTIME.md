# Victoriametrics Cloud

Generated Source Runtime SDK scaffold for `victoriametrics_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/victoriametrics_cloud`
- Health endpoint: `/source-runtimes/health?source_id=victoriametrics_cloud`
- Source health receipt: `sources/victoriametrics_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `victoriametrics_cloud.evidence_cas_reference`

## Families

- `users`, emits `victoriametrics_cloud.users`, reads `/v1/users`
- `accounts`, emits `victoriametrics_cloud.accounts`, reads `/v1/accounts`
- `records`, emits `victoriametrics_cloud.records`, reads `/v1/records`
- `policies`, emits `victoriametrics_cloud.policies`, reads `/v1/policies`
- `audit_events`, emits `victoriametrics_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/victoriametrics_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
