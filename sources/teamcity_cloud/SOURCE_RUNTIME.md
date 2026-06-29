# Teamcity Cloud

Generated Source Runtime SDK scaffold for `teamcity_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/teamcity_cloud`
- Health endpoint: `/source-runtimes/health?source_id=teamcity_cloud`
- Source health receipt: `sources/teamcity_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `teamcity_cloud.evidence_cas_reference`

## Families

- `users`, emits `teamcity_cloud.users`, reads `/v1/users`
- `projects`, emits `teamcity_cloud.projects`, reads `/v1/projects`
- `repositories`, emits `teamcity_cloud.repositories`, reads `/v1/repositories`
- `deployments`, emits `teamcity_cloud.deployments`, reads `/v1/deployments`
- `audit_events`, emits `teamcity_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/teamcity_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
