# Env0

Generated Source Runtime SDK scaffold for `env0`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/env0`
- Health endpoint: `/source-runtimes/health?source_id=env0`
- Source health receipt: `sources/env0/source_health_receipt.json`
- EvidenceCAS reference kind: `env0.evidence_cas_reference`

## Families

- `users`, emits `env0.users`, reads `/v1/users`
- `projects`, emits `env0.projects`, reads `/v1/projects`
- `repositories`, emits `env0.repositories`, reads `/v1/repositories`
- `deployments`, emits `env0.deployments`, reads `/v1/deployments`
- `audit_events`, emits `env0.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/env0 ./internal/sourceprojection -count=1`
- `make catalog-check`
