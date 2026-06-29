# Raygun

Generated Source Runtime SDK scaffold for `raygun`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/raygun`
- Health endpoint: `/source-runtimes/health?source_id=raygun`
- Source health receipt: `sources/raygun/source_health_receipt.json`
- EvidenceCAS reference kind: `raygun.evidence_cas_reference`

## Families

- `users`, emits `raygun.users`, reads `/v1/users`
- `projects`, emits `raygun.projects`, reads `/v1/projects`
- `repositories`, emits `raygun.repositories`, reads `/v1/repositories`
- `deployments`, emits `raygun.deployments`, reads `/v1/deployments`
- `audit_events`, emits `raygun.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/raygun ./internal/sourceprojection -count=1`
- `make catalog-check`
