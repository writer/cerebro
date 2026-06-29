# Jfrog Artifactory

Generated Source Runtime SDK scaffold for `jfrog_artifactory`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/jfrog_artifactory`
- Health endpoint: `/source-runtimes/health?source_id=jfrog_artifactory`
- Source health receipt: `sources/jfrog_artifactory/source_health_receipt.json`
- EvidenceCAS reference kind: `jfrog_artifactory.evidence_cas_reference`

## Families

- `users`, emits `jfrog_artifactory.users`, reads `/v1/users`
- `projects`, emits `jfrog_artifactory.projects`, reads `/v1/projects`
- `repositories`, emits `jfrog_artifactory.repositories`, reads `/v1/repositories`
- `deployments`, emits `jfrog_artifactory.deployments`, reads `/v1/deployments`
- `audit_events`, emits `jfrog_artifactory.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/jfrog_artifactory ./internal/sourceprojection -count=1`
- `make catalog-check`
