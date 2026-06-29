# K6 Cloud

Generated Source Runtime SDK scaffold for `k6_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/k6_cloud`
- Health endpoint: `/source-runtimes/health?source_id=k6_cloud`
- Source health receipt: `sources/k6_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `k6_cloud.evidence_cas_reference`

## Families

- `users`, emits `k6_cloud.users`, reads `/v1/users`
- `projects`, emits `k6_cloud.projects`, reads `/v1/projects`
- `repositories`, emits `k6_cloud.repositories`, reads `/v1/repositories`
- `deployments`, emits `k6_cloud.deployments`, reads `/v1/deployments`
- `audit_events`, emits `k6_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/k6_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
