# Semaphore CI

Generated Source Runtime SDK scaffold for `semaphore_ci`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/semaphore_ci`
- Health endpoint: `/source-runtimes/health?source_id=semaphore_ci`
- Source health receipt: `sources/semaphore_ci/source_health_receipt.json`
- EvidenceCAS reference kind: `semaphore_ci.evidence_cas_reference`

## Families

- `users`, emits `semaphore_ci.users`, reads `/v1/users`
- `projects`, emits `semaphore_ci.projects`, reads `/v1/projects`
- `repositories`, emits `semaphore_ci.repositories`, reads `/v1/repositories`
- `deployments`, emits `semaphore_ci.deployments`, reads `/v1/deployments`
- `audit_events`, emits `semaphore_ci.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/semaphore_ci ./internal/sourceprojection -count=1`
- `make catalog-check`
