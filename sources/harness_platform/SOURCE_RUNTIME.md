# Harness Platform

Generated Source Runtime SDK scaffold for `harness_platform`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/harness_platform`
- Health endpoint: `/source-runtimes/health?source_id=harness_platform`
- Source health receipt: `sources/harness_platform/source_health_receipt.json`
- EvidenceCAS reference kind: `harness_platform.evidence_cas_reference`

## Families

- `users`, emits `harness_platform.users`, reads `/v1/users`
- `projects`, emits `harness_platform.projects`, reads `/v1/projects`
- `repositories`, emits `harness_platform.repositories`, reads `/v1/repositories`
- `deployments`, emits `harness_platform.deployments`, reads `/v1/deployments`
- `audit_events`, emits `harness_platform.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/harness_platform ./internal/sourceprojection -count=1`
- `make catalog-check`
