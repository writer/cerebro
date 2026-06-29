# Octopus Deploy

Generated Source Runtime SDK scaffold for `octopus_deploy`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/octopus_deploy`
- Health endpoint: `/source-runtimes/health?source_id=octopus_deploy`
- Source health receipt: `sources/octopus_deploy/source_health_receipt.json`
- EvidenceCAS reference kind: `octopus_deploy.evidence_cas_reference`

## Families

- `users`, emits `octopus_deploy.users`, reads `/v1/users`
- `projects`, emits `octopus_deploy.projects`, reads `/v1/projects`
- `repositories`, emits `octopus_deploy.repositories`, reads `/v1/repositories`
- `deployments`, emits `octopus_deploy.deployments`, reads `/v1/deployments`
- `audit_events`, emits `octopus_deploy.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/octopus_deploy ./internal/sourceprojection -count=1`
- `make catalog-check`
