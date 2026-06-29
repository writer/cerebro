# Cloudbees CI

Generated Source Runtime SDK scaffold for `cloudbees_ci`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cloudbees_ci`
- Health endpoint: `/source-runtimes/health?source_id=cloudbees_ci`
- Source health receipt: `sources/cloudbees_ci/source_health_receipt.json`
- EvidenceCAS reference kind: `cloudbees_ci.evidence_cas_reference`

## Families

- `users`, emits `cloudbees_ci.users`, reads `/v1/users`
- `projects`, emits `cloudbees_ci.projects`, reads `/v1/projects`
- `repositories`, emits `cloudbees_ci.repositories`, reads `/v1/repositories`
- `deployments`, emits `cloudbees_ci.deployments`, reads `/v1/deployments`
- `audit_events`, emits `cloudbees_ci.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cloudbees_ci ./internal/sourceprojection -count=1`
- `make catalog-check`
