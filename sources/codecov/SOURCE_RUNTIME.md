# Codecov

Generated Source Runtime SDK scaffold for `codecov`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/codecov`
- Health endpoint: `/source-runtimes/health?source_id=codecov`
- Source health receipt: `sources/codecov/source_health_receipt.json`
- EvidenceCAS reference kind: `codecov.evidence_cas_reference`

## Families

- `users`, emits `codecov.users`, reads `/v1/users`
- `projects`, emits `codecov.projects`, reads `/v1/projects`
- `repositories`, emits `codecov.repositories`, reads `/v1/repositories`
- `deployments`, emits `codecov.deployments`, reads `/v1/deployments`
- `audit_events`, emits `codecov.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/codecov ./internal/sourceprojection -count=1`
- `make catalog-check`
