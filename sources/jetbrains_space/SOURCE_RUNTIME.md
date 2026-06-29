# Jetbrains Space

Generated Source Runtime SDK scaffold for `jetbrains_space`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/jetbrains_space`
- Health endpoint: `/source-runtimes/health?source_id=jetbrains_space`
- Source health receipt: `sources/jetbrains_space/source_health_receipt.json`
- EvidenceCAS reference kind: `jetbrains_space.evidence_cas_reference`

## Families

- `users`, emits `jetbrains_space.users`, reads `/v1/users`
- `projects`, emits `jetbrains_space.projects`, reads `/v1/projects`
- `repositories`, emits `jetbrains_space.repositories`, reads `/v1/repositories`
- `deployments`, emits `jetbrains_space.deployments`, reads `/v1/deployments`
- `audit_events`, emits `jetbrains_space.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/jetbrains_space ./internal/sourceprojection -count=1`
- `make catalog-check`
