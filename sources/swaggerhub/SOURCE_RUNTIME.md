# Swaggerhub

Generated Source Runtime SDK scaffold for `swaggerhub`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/swaggerhub`
- Health endpoint: `/source-runtimes/health?source_id=swaggerhub`
- Source health receipt: `sources/swaggerhub/source_health_receipt.json`
- EvidenceCAS reference kind: `swaggerhub.evidence_cas_reference`

## Families

- `users`, emits `swaggerhub.users`, reads `/v1/users`
- `projects`, emits `swaggerhub.projects`, reads `/v1/projects`
- `repositories`, emits `swaggerhub.repositories`, reads `/v1/repositories`
- `deployments`, emits `swaggerhub.deployments`, reads `/v1/deployments`
- `audit_events`, emits `swaggerhub.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/swaggerhub ./internal/sourceprojection -count=1`
- `make catalog-check`
