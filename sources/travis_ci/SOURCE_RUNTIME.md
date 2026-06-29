# Travis CI

Generated Source Runtime SDK scaffold for `travis_ci`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/travis_ci`
- Health endpoint: `/source-runtimes/health?source_id=travis_ci`
- Source health receipt: `sources/travis_ci/source_health_receipt.json`
- EvidenceCAS reference kind: `travis_ci.evidence_cas_reference`

## Families

- `users`, emits `travis_ci.users`, reads `/v1/users`
- `projects`, emits `travis_ci.projects`, reads `/v1/projects`
- `repositories`, emits `travis_ci.repositories`, reads `/v1/repositories`
- `deployments`, emits `travis_ci.deployments`, reads `/v1/deployments`
- `audit_events`, emits `travis_ci.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/travis_ci ./internal/sourceprojection -count=1`
- `make catalog-check`
