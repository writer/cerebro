# Flagsmith Cloud

Generated Source Runtime SDK scaffold for `flagsmith_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/flagsmith_cloud`
- Health endpoint: `/source-runtimes/health?source_id=flagsmith_cloud`
- Source health receipt: `sources/flagsmith_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `flagsmith_cloud.evidence_cas_reference`

## Families

- `users`, emits `flagsmith_cloud.users`, reads `/v1/users`
- `projects`, emits `flagsmith_cloud.projects`, reads `/v1/projects`
- `repositories`, emits `flagsmith_cloud.repositories`, reads `/v1/repositories`
- `deployments`, emits `flagsmith_cloud.deployments`, reads `/v1/deployments`
- `audit_events`, emits `flagsmith_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/flagsmith_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
