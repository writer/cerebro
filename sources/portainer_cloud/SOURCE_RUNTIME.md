# Portainer Cloud

Generated Source Runtime SDK scaffold for `portainer_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/portainer_cloud`
- Health endpoint: `/source-runtimes/health?source_id=portainer_cloud`
- Source health receipt: `sources/portainer_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `portainer_cloud.evidence_cas_reference`

## Families

- `users`, emits `portainer_cloud.users`, reads `/v1/users`
- `projects`, emits `portainer_cloud.projects`, reads `/v1/projects`
- `repositories`, emits `portainer_cloud.repositories`, reads `/v1/repositories`
- `deployments`, emits `portainer_cloud.deployments`, reads `/v1/deployments`
- `audit_events`, emits `portainer_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/portainer_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
