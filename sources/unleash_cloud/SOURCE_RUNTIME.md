# Unleash Cloud

Generated Source Runtime SDK scaffold for `unleash_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/unleash_cloud`
- Health endpoint: `/source-runtimes/health?source_id=unleash_cloud`
- Source health receipt: `sources/unleash_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `unleash_cloud.evidence_cas_reference`

## Families

- `users`, emits `unleash_cloud.users`, reads `/v1/users`
- `projects`, emits `unleash_cloud.projects`, reads `/v1/projects`
- `repositories`, emits `unleash_cloud.repositories`, reads `/v1/repositories`
- `deployments`, emits `unleash_cloud.deployments`, reads `/v1/deployments`
- `audit_events`, emits `unleash_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/unleash_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
