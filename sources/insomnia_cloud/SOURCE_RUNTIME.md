# Insomnia Cloud

Generated Source Runtime SDK scaffold for `insomnia_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/insomnia_cloud`
- Health endpoint: `/source-runtimes/health?source_id=insomnia_cloud`
- Source health receipt: `sources/insomnia_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `insomnia_cloud.evidence_cas_reference`

## Families

- `users`, emits `insomnia_cloud.users`, reads `/v1/users`
- `projects`, emits `insomnia_cloud.projects`, reads `/v1/projects`
- `repositories`, emits `insomnia_cloud.repositories`, reads `/v1/repositories`
- `deployments`, emits `insomnia_cloud.deployments`, reads `/v1/deployments`
- `audit_events`, emits `insomnia_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/insomnia_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
