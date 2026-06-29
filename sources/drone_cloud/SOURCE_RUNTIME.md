# Drone Cloud

Generated Source Runtime SDK scaffold for `drone_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/drone_cloud`
- Health endpoint: `/source-runtimes/health?source_id=drone_cloud`
- Source health receipt: `sources/drone_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `drone_cloud.evidence_cas_reference`

## Families

- `users`, emits `drone_cloud.users`, reads `/v1/users`
- `projects`, emits `drone_cloud.projects`, reads `/v1/projects`
- `repositories`, emits `drone_cloud.repositories`, reads `/v1/repositories`
- `deployments`, emits `drone_cloud.deployments`, reads `/v1/deployments`
- `audit_events`, emits `drone_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/drone_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
