# Devtron

Generated Source Runtime SDK scaffold for `devtron`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/devtron`
- Health endpoint: `/source-runtimes/health?source_id=devtron`
- Source health receipt: `sources/devtron/source_health_receipt.json`
- EvidenceCAS reference kind: `devtron.evidence_cas_reference`

## Families

- `users`, emits `devtron.users`, reads `/v1/users`
- `projects`, emits `devtron.projects`, reads `/v1/projects`
- `repositories`, emits `devtron.repositories`, reads `/v1/repositories`
- `deployments`, emits `devtron.deployments`, reads `/v1/deployments`
- `audit_events`, emits `devtron.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/devtron ./internal/sourceprojection -count=1`
- `make catalog-check`
